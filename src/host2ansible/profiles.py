"""Load application profiles that say what to collect and how to render it."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from host2ansible.guard import ReadOnlyViolation, assert_read_only
from host2ansible.paths import PathDenied, assert_detect_path, assert_file, assert_glob, assert_tree

_NAME = __import__("re").compile(r"[a-z][a-z0-9_]{0,40}\Z")
_UNIT = __import__("re").compile(r"[a-zA-Z0-9][a-zA-Z0-9@._-]{0,80}\.service\Z")

_TOP = {"name", "description", "read_only", "detect", "collect", "ansible"}
_DETECT_ITEM = {"path", "systemd", "command_ok"}
_COLLECT = {"trees", "files", "commands", "globs"}
_TREE = {"path", "optional", "exclude_suffixes", "exclude_names", "max_files", "max_depth"}
_FILE = {"path", "optional"}
_COMMAND = {"id", "argv", "optional"}
_GLOB = {"root", "names", "maxdepth", "optional"}
_ANSIBLE = {"apply", "packages", "service", "validate", "note"}
_SERVICE = {"name", "names", "state", "enabled"}
_VALIDATE = {"argv"}


class ProfileError(Exception):
    """The profile file is not usable."""


@dataclass(frozen=True)
class DetectCheck:
    kind: str
    path: str | None = None
    unit: str | None = None
    argv: tuple[str, ...] | None = None


@dataclass(frozen=True)
class TreeSpec:
    path: str
    optional: bool
    exclude_suffixes: tuple[str, ...]
    exclude_names: tuple[str, ...]
    max_files: int
    max_depth: int


@dataclass(frozen=True)
class FileSpec:
    path: str
    optional: bool


@dataclass(frozen=True)
class CommandSpec:
    id: str
    argv: tuple[str, ...]
    optional: bool


@dataclass(frozen=True)
class GlobSpec:
    root: str
    names: tuple[str, ...]
    maxdepth: int
    optional: bool


@dataclass(frozen=True)
class ServiceSpec:
    name: str | None
    names: dict[str, str]
    state: str
    enabled: bool


@dataclass(frozen=True)
class ValidateSpec:
    argv: tuple[str, ...]


@dataclass(frozen=True)
class AnsibleSpec:
    apply: str
    packages: dict[str, tuple[str, ...]]
    service: ServiceSpec | None
    validate: tuple[ValidateSpec, ...]
    note: str


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    source: str
    detect: tuple[DetectCheck, ...]
    trees: tuple[TreeSpec, ...]
    files: tuple[FileSpec, ...]
    commands: tuple[CommandSpec, ...]
    globs: tuple[GlobSpec, ...]
    ansible: AnsibleSpec


def builtin_dir() -> Path:
    return Path(__file__).resolve().parent / "builtin_profiles"


def load_builtin() -> list[Profile]:
    return [load_profile(path) for path in sorted(builtin_dir().glob("*.yaml"))]


def load_many(files: list[Path], directories: list[Path]) -> list[Profile]:
    """Builtins first. User profiles override by name. Duplicates in user input fail."""
    by_name = {profile.name: profile for profile in load_builtin()}
    user_names: dict[str, str] = {}
    paths: list[Path] = []
    for directory in directories:
        if not directory.is_dir():
            raise ProfileError(f"profile dir not found: {directory}")
        paths.extend(sorted(directory.glob("*.yaml")))
    paths.extend(files)
    for path in paths:
        profile = load_profile(path)
        if profile.name in user_names:
            raise ProfileError(
                f"{profile.name} is defined in both {user_names[profile.name]} and {path}"
            )
        user_names[profile.name] = str(path)
        by_name[profile.name] = profile
    return [by_name[name] for name in sorted(by_name)]


def load_profile(path: Path) -> Profile:
    if not path.is_file():
        raise ProfileError(f"profile not found: {path}")
    raw_bytes = path.read_bytes()
    if len(raw_bytes) > 64_000:
        raise ProfileError(f"{path} is larger than 64KB")
    try:
        data = yaml.safe_load(raw_bytes.decode("utf-8"))
    except (UnicodeError, yaml.YAMLError) as exc:
        raise ProfileError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ProfileError(f"{path} must be a mapping")
    unknown = set(data) - _TOP
    if unknown:
        raise ProfileError(f"{path} has unknown keys: {sorted(unknown)}")
    if data.get("read_only") is not True:
        raise ProfileError(f"{path} must set read_only: true")
    name = _name(data.get("name"), path)
    description = data.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ProfileError(f"{path} needs a description")
    try:
        return Profile(
            name=name,
            description=description.strip(),
            source=str(path),
            detect=_detect(data.get("detect"), path),
            trees=_trees(data.get("collect"), path),
            files=_files(data.get("collect"), path),
            commands=_commands(data.get("collect"), path),
            globs=_globs(data.get("collect"), path),
            ansible=_ansible(data.get("ansible"), path),
        )
    except (PathDenied, ReadOnlyViolation) as exc:
        raise ProfileError(f"{path}: {exc}") from exc


def _mapping(value: object, path: Path, label: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ProfileError(f"{path} {label} must be a mapping")
    return value


def _name(value: object, path: Path) -> str:
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise ProfileError(f"{path} name must match {_NAME.pattern}")
    return value


def _detect(value: object, path: Path) -> tuple[DetectCheck, ...]:
    block = _mapping(value, path, "detect")
    if set(block) - {"any"}:
        raise ProfileError(f"{path} detect only accepts 'any'")
    items = block.get("any")
    if not isinstance(items, list) or not items:
        raise ProfileError(f"{path} detect.any must be a non-empty list")
    checks: list[DetectCheck] = []
    for item in items:
        if not isinstance(item, dict) or len(item) != 1 or set(item) - _DETECT_ITEM:
            raise ProfileError(f"{path} each detect item needs exactly one of {sorted(_DETECT_ITEM)}")
        if "path" in item:
            if not isinstance(item["path"], str):
                raise ProfileError(f"{path} detect path must be a string")
            checks.append(DetectCheck("path", path=assert_detect_path(item["path"])))
        elif "systemd" in item:
            unit = item["systemd"]
            if not isinstance(unit, str) or not _UNIT.fullmatch(unit):
                raise ProfileError(f"{path} systemd unit must look like name.service")
            checks.append(DetectCheck("systemd", unit=unit))
        else:
            argv = _argv(item.get("command_ok"), path)
            assert_read_only(list(argv))
            checks.append(DetectCheck("command_ok", argv=argv))
    return tuple(checks)


def _collect(value: object, path: Path) -> dict:
    block = _mapping(value, path, "collect")
    unknown = set(block) - _COLLECT
    if unknown:
        raise ProfileError(f"{path} collect has unknown keys: {sorted(unknown)}")
    return block


def _trees(value: object, path: Path) -> tuple[TreeSpec, ...]:
    block = _collect(value, path)
    items = block.get("trees", [])
    if items is None:
        items = []
    if not isinstance(items, list):
        raise ProfileError(f"{path} collect.trees must be a list")
    specs: list[TreeSpec] = []
    for item in items:
        if not isinstance(item, dict) or set(item) - _TREE or "path" not in item:
            raise ProfileError(f"{path} tree needs a path and only known keys")
        suffixes = tuple(item.get("exclude_suffixes") or [])
        names = tuple(item.get("exclude_names") or [])
        if not all(isinstance(x, str) and x for x in suffixes + names):
            raise ProfileError(f"{path} tree excludes must be strings")
        max_files = int(item.get("max_files", 400))
        max_depth = int(item.get("max_depth", 6))
        if not 1 <= max_files <= 400 or not 1 <= max_depth <= 8:
            raise ProfileError(f"{path} tree limits are max_files<=400 and max_depth<=8")
        specs.append(
            TreeSpec(
                path=assert_tree(item["path"]),
                optional=bool(item.get("optional", False)),
                exclude_suffixes=suffixes,
                exclude_names=names,
                max_files=max_files,
                max_depth=max_depth,
            )
        )
    return tuple(specs)


def _files(value: object, path: Path) -> tuple[FileSpec, ...]:
    items = _collect(value, path).get("files", []) or []
    if not isinstance(items, list):
        raise ProfileError(f"{path} collect.files must be a list")
    specs: list[FileSpec] = []
    for item in items:
        if not isinstance(item, dict) or set(item) - _FILE or not isinstance(item.get("path"), str):
            raise ProfileError(f"{path} file entry needs a path")
        specs.append(FileSpec(path=assert_file(item["path"]), optional=bool(item.get("optional", False))))
    return tuple(specs)


def _commands(value: object, path: Path) -> tuple[CommandSpec, ...]:
    items = _collect(value, path).get("commands", []) or []
    if not isinstance(items, list):
        raise ProfileError(f"{path} collect.commands must be a list")
    specs: list[CommandSpec] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or set(item) - _COMMAND:
            raise ProfileError(f"{path} command has unknown keys")
        ident = item.get("id")
        if not isinstance(ident, str) or not _NAME.fullmatch(ident) or ident in seen:
            raise ProfileError(f"{path} command id must be a unique safe name")
        seen.add(ident)
        argv = _argv(item.get("argv"), path)
        assert_read_only(list(argv))
        specs.append(CommandSpec(id=ident, argv=argv, optional=bool(item.get("optional", False))))
    return tuple(specs)


def _globs(value: object, path: Path) -> tuple[GlobSpec, ...]:
    items = _collect(value, path).get("globs", []) or []
    if not isinstance(items, list):
        raise ProfileError(f"{path} collect.globs must be a list")
    specs: list[GlobSpec] = []
    for item in items:
        if not isinstance(item, dict) or set(item) - _GLOB or "root" not in item:
            raise ProfileError(f"{path} glob needs a root")
        names = tuple(item.get("names") or [])
        if not all(isinstance(name, str) for name in names):
            raise ProfileError(f"{path} glob names must be strings")
        maxdepth = int(item.get("maxdepth", 4))
        if not 1 <= maxdepth <= 8:
            raise ProfileError(f"{path} glob maxdepth must be 1..8")
        specs.append(
            GlobSpec(
                root=assert_glob(str(item["root"]), names),
                names=names,
                maxdepth=maxdepth,
                optional=bool(item.get("optional", False)),
            )
        )
    return tuple(specs)


def _ansible(value: object, path: Path) -> AnsibleSpec:
    block = _mapping(value, path, "ansible")
    unknown = set(block) - _ANSIBLE
    if unknown:
        raise ProfileError(f"{path} ansible has unknown keys: {sorted(unknown)}")
    apply = block.get("apply")
    if apply not in {"auto", "review"}:
        raise ProfileError(f"{path} ansible.apply must be auto or review")
    packages = _packages(block.get("packages", {}), path)
    service = _service(block.get("service"), path)
    validate = _validate(block.get("validate", []), path)
    note = block.get("note") or ""
    if not isinstance(note, str):
        raise ProfileError(f"{path} ansible.note must be a string")
    return AnsibleSpec(apply=apply, packages=packages, service=service, validate=validate, note=note.strip())


def _packages(value: object, path: Path) -> dict[str, tuple[str, ...]]:
    if value is None:
        return {}
    if not isinstance(value, dict) or set(value) - {"debian", "redhat"}:
        raise ProfileError(f"{path} packages only accepts debian and redhat")
    out: dict[str, tuple[str, ...]] = {}
    for family, names in value.items():
        if not isinstance(names, list) or not all(_pkg(name) for name in names):
            raise ProfileError(f"{path} package names must be simple strings")
        out[str(family)] = tuple(names)
    return out


def _pkg(name: object) -> bool:
    return isinstance(name, str) and __import__("re").fullmatch(r"[a-z0-9][a-z0-9+.-]{0,60}", name) is not None


def _service(value: object, path: Path) -> ServiceSpec | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - _SERVICE:
        raise ProfileError(f"{path} service has unknown keys")
    state = value.get("state", "started")
    enabled = value.get("enabled", True)
    if state not in {"started", "stopped"} or not isinstance(enabled, bool):
        raise ProfileError(f"{path} service state/enabled is invalid")
    name = value.get("name")
    names = value.get("names")
    if (name is None) == (names is None):
        raise ProfileError(f"{path} service needs name or names, not both")
    if name is not None and not _unit_name(name):
        raise ProfileError(f"{path} service.name is invalid")
    resolved: dict[str, str] = {}
    if isinstance(names, dict):
        if set(names) - {"debian", "redhat"} or not names:
            raise ProfileError(f"{path} service.names only accepts debian and redhat")
        for family, unit in names.items():
            if not _unit_name(unit):
                raise ProfileError(f"{path} service.names.{family} is invalid")
            resolved[str(family)] = str(unit)
        name = None
    elif names is not None:
        raise ProfileError(f"{path} service.names must be a mapping")
    return ServiceSpec(name=name if isinstance(name, str) else None, names=resolved, state=state, enabled=enabled)


def _unit_name(name: object) -> bool:
    return isinstance(name, str) and __import__("re").fullmatch(r"[a-zA-Z0-9@._-]{1,80}", name) is not None


def _validate(value: object, path: Path) -> tuple[ValidateSpec, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ProfileError(f"{path} validate must be a list")
    specs: list[ValidateSpec] = []
    for item in value:
        if not isinstance(item, dict) or set(item) - _VALIDATE:
            raise ProfileError(f"{path} validate item only accepts argv")
        argv = _argv(item.get("argv"), path)
        assert_read_only(list(argv))
        specs.append(ValidateSpec(argv=argv))
    return tuple(specs)


def _argv(value: object, path: Path) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise ProfileError(f"{path} argv must be a non-empty list of strings")
    if len(value) > 32 or any(len(item) > 200 for item in value):
        raise ProfileError(f"{path} argv is too large")
    return tuple(value)
