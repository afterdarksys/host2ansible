"""Read-only collection. Nothing in this module writes to the target."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from host2ansible import __version__
from host2ansible.guard import assert_read_only
from host2ansible.paths import PathDenied, assert_file
from host2ansible.profiles import Profile, ServiceSpec
from host2ansible.redact import looks_like_private_key
from host2ansible.transport import MAX_COMMAND_BYTES

SCHEMA = 1
MAX_FILE_BYTES = 512 * 1024
MAX_STORED_BYTES = 32 * 1024 * 1024
MAX_COMMANDS = 2000
_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}\Z")


class InvestigateError(Exception):
    """Collection stopped. The target was not modified by this tool."""


def tree_find_argv(root: str, max_depth: int) -> list[str]:
    return [
        "find",
        "-P",
        root,
        "-maxdepth",
        str(max_depth),
        "-xdev",
        "(",
        "(",
        "-type",
        "f",
        "-size",
        "-512k",
        ")",
        "-o",
        "(",
        "-type",
        "l",
        ")",
        ")",
        "-print0",
    ]


def oversized_find_argv(root: str, max_depth: int) -> list[str]:
    return [
        "find",
        "-P",
        root,
        "-maxdepth",
        str(max_depth),
        "-xdev",
        "-type",
        "f",
        "-size",
        "+511k",
        "-print0",
    ]


def glob_find_argv(root: str, maxdepth: int, names: tuple[str, ...]) -> list[str]:
    argv = ["find", "-P", root, "-maxdepth", str(maxdepth), "-xdev", "("]
    for index, name in enumerate(names):
        if index:
            argv.append("-o")
        argv.extend(["-name", name])
    argv.extend([")", "-type", "f", "-size", "-512k", "-print0"])
    return argv


def parse_os_release(text: str) -> dict[str, str]:
    info: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        info[key] = value
    return info


def os_family(info: dict[str, str]) -> str:
    tokens = set((info.get("ID", "") + " " + info.get("ID_LIKE", "")).replace(",", " ").split())
    if tokens & {"debian", "ubuntu", "linuxmint", "raspbian"}:
        return "debian"
    if tokens & {"rhel", "fedora", "centos", "rocky", "almalinux", "ol"}:
        return "redhat"
    return "unknown"


def safe_hostname(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9.-]", "-", name.strip().splitlines()[0] if name.strip() else "")
    cleaned = cleaned.strip(".-")[:63]
    if not cleaned or not _HOST.fullmatch(cleaned):
        return "host"
    return cleaned


def parse_addresses(text: str) -> list[str]:
    found: list[str] = []
    for line in text.splitlines():
        parts = line.split()
        kind = "inet6" if "inet6" in parts else "inet" if "inet" in parts else ""
        if not kind:
            continue
        idx = parts.index(kind)
        if idx + 1 >= len(parts):
            continue
        ip = parts[idx + 1].split("/")[0]
        if ip.startswith("127.") or ip == "::1" or ip.lower().startswith("fe80:"):
            continue
        if ip not in found:
            found.append(ip)
    return found


class Session:
    def __init__(self, transport, timeout: float):
        self.transport = transport
        self.timeout = timeout
        self.gaps: list[str] = []
        self.transcript: list[dict] = []
        self.blobs: dict[str, bytes] = {}
        self.stored = 0

    def run(self, argv: list[str], fatal: bool = False) -> CommandResult:
        assert_read_only(argv)
        if len(self.transcript) >= MAX_COMMANDS:
            raise InvestigateError("command cap exceeded; refusing to continue")
        result = self.transport.run(argv, self.timeout)
        self.transcript.append(
            {
                "argv": argv,
                "rc": result.rc,
                "timed_out": result.timed_out,
                "truncated": result.truncated,
                "bytes": len(result.stdout),
            }
        )
        if fatal and (result.timed_out or result.rc != 0):
            detail = result.stderr.decode("utf-8", "replace")[:200]
            raise InvestigateError(f"required command failed ({result.rc}): {argv[0]} {detail}")
        return result

    def exists(self, path: str) -> bool:
        return self.run(["test", "-e", path]).rc == 0

    def stat(self, path: str) -> tuple[int, str, str, str] | None:
        # -L: /etc/os-release is often a symlink. Plain stat reports the link's length.
        result = self.run(["stat", "-L", "-c", "%s %a %U %G", "--", path])
        if result.rc != 0 or result.timed_out:
            return None
        parts = result.stdout.split()
        if len(parts) != 4 or not parts[0].isdigit() or not parts[1].isdigit():
            return None
        mode = parts[1].decode()
        if len(mode) > 4:
            return None
        owner, group = (part.decode("utf-8", "replace") for part in parts[2:])
        if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*[$]?", name) or name == "UNKNOWN"
               for name in (owner, group)):
            self.gaps.append(f"unresolved file ownership: {path}")
            return None
        return int(parts[0]), mode.zfill(4), owner, group

    def read_file(self, path: str) -> tuple[bytes, str, str, str] | None:
        try:
            path = assert_file(path)
        except PathDenied as exc:
            self.gaps.append(str(exc))
            return None
        meta = self.stat(path)
        if meta is None:
            return None
        size, mode, owner, group = meta
        if size > MAX_FILE_BYTES:
            self.gaps.append(f"{path} is {size} bytes; not collected")
            return None
        header = self.run(["head", "-c", "48", "--", path])
        if header.rc != 0:
            self.gaps.append(f"could not read {path}")
            return None
        if looks_like_private_key(header.stdout):
            self.gaps.append(f"private key not collected: {path}")
            return None
        if size <= 48:
            data = header.stdout
        else:
            body = self.run(["head", "-c", str(size), "--", path])
            if body.rc != 0 or len(body.stdout) != size:
                self.gaps.append(f"short read of {path}")
                return None
            data = body.stdout
        return data, mode, owner, group

    def keep(self, relpath: str, data: bytes) -> None:
        self.stored += len(data)
        if self.stored > MAX_STORED_BYTES:
            raise InvestigateError("investigation exceeded 32MB; refusing to continue")
        self.blobs[relpath] = data

    def paths_from(self, result: CommandResult, label: str) -> list[str] | None:
        if result.timed_out or result.rc != 0:
            self.gaps.append(f"{label} failed rc={result.rc}")
            return None
        if result.truncated or len(result.stdout) >= MAX_COMMAND_BYTES:
            self.gaps.append(f"{label} output was truncated; that tree was not deployed")
            return None
        paths: list[str] = []
        for raw in result.stdout.split(b"\0"):
            if not raw:
                continue
            if b"\n" in raw:
                raise InvestigateError("newline in a remote path; refusing to continue")
            try:
                text = raw.decode("utf-8")
            except UnicodeError as exc:
                raise InvestigateError(f"remote path is not utf-8 under {label}") from exc
            paths.append(text)
        return paths


def investigate(transport, profiles: list[Profile], parent: Path, timeout: float, force: bool) -> Path:
    session = Session(transport, timeout)
    uname = session.run(["uname", "-s"], fatal=True)
    if uname.stdout.strip() != b"Linux":
        raise InvestigateError(f"only Linux is supported, got {uname.stdout!r}")
    os_raw = session.read_file("/etc/os-release")
    if os_raw is None:
        raise InvestigateError("could not read /etc/os-release")
    try:
        os_text = os_raw[0].decode("utf-8")
    except UnicodeError as exc:
        raise InvestigateError("/etc/os-release is not utf-8") from exc
    info = parse_os_release(os_text)
    if not info.get("ID"):
        raise InvestigateError("/etc/os-release has no ID")
    family = os_family(info)
    host_raw = session.read_file("/etc/hostname")
    hostname = safe_hostname(host_raw[0].decode("utf-8", "replace")) if host_raw else "host"
    out = parent / hostname
    if out.exists() and not out.is_dir():
        raise InvestigateError(f"{out} is not a directory")
    if out.exists() and any(out.iterdir()) and not force:
        raise InvestigateError(f"{out} already exists; pass --force to replace it")
    addresses = _addresses(session)
    services = [_service(session, profile, family) for profile in profiles]
    services = [item for item in services if item is not None]
    services.extend(_security(session))
    bundle = {
        "schema": SCHEMA,
        "tool_version": __version__,
        "hostname": hostname,
        "source": {
            "transport": transport.label,
            "addresses": addresses,
            "investigated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "os": {
            "id": info.get("ID", ""),
            "id_like": info.get("ID_LIKE", ""),
            "version_id": info.get("VERSION_ID", ""),
            "pretty": info.get("PRETTY_NAME", ""),
            "family": family,
        },
        "system": _system(session, uname),
        "firewall": _firewall(session),
        "services": services,
        "gaps": session.gaps,
        "transcript": session.transcript,
    }
    _flush(out, bundle, session.blobs)
    return out


def _addresses(session: Session) -> list[str]:
    found: list[str] = []
    for version in ("-4", "-6"):
        result = session.run(["ip", "-o", version, "addr", "show"])
        if result.rc != 0:
            session.gaps.append(f"ip {version} addr show failed")
            continue
        for ip in parse_addresses(result.stdout.decode("utf-8", "replace")):
            if ip not in found:
                found.append(ip)
    return found


def _system(session: Session, uname: CommandResult) -> dict:
    evidence = {"uname": uname.stdout.decode("utf-8", "replace").strip()}
    full = session.run(["uname", "-a"])
    if full.rc == 0:
        evidence["uname_a"] = full.stdout.decode("utf-8", "replace").strip()
    packages = _packages(session)
    if packages is not None:
        session.keep("evidence/packages.txt", packages)
    units = session.run(["systemctl", "list-unit-files", "--state=enabled", "--no-pager", "--plain"])
    if units.rc == 0 and not units.truncated:
        session.keep("evidence/enabled-units.txt", units.stdout)
    else:
        session.gaps.append("enabled systemd units were not listed")
    listening = session.run(["ss", "-H", "-lntu"])
    if listening.rc == 0 and not listening.truncated:
        session.keep("evidence/listening.txt", listening.stdout)
    else:
        session.gaps.append("listening sockets were not listed")
    return {"evidence": evidence}


def _packages(session: Session) -> bytes | None:
    deb = session.run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"])
    if deb.rc == 0 and not deb.truncated:
        return deb.stdout
    rpm = session.run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
    if rpm.rc == 0 and not rpm.truncated:
        return rpm.stdout
    session.gaps.append("package list was not collected")
    return None


def _service(session: Session, profile: Profile, family: str) -> dict | None:
    hits = _detect(session, profile)
    if not hits:
        return None
    files: list[dict] = []
    links: list[dict] = []
    omitted = False
    for spec in profile.trees:
        found, linked, stop = _tree(session, profile.name, spec)
        files.extend(found)
        links.extend(linked)
        omitted = omitted or stop
    for spec in profile.files:
        record = _one_file(session, profile.name, spec.path, spec.optional)
        if record:
            files.append(record)
    for spec in profile.globs:
        found, stop = _glob(session, profile.name, spec)
        files.extend(found)
        omitted = omitted or stop
    if omitted:
        session.gaps.append(f"{profile.name} was detected but not rendered; collection was incomplete")
        return None
    commands = []
    for spec in profile.commands:
        result = session.run(list(spec.argv))
        rel = f"evidence/services/{profile.name}/{spec.id}.txt"
        session.keep(rel, result.stdout)
        if result.stderr:
            session.keep(f"evidence/services/{profile.name}/{spec.id}.err", result.stderr[:8192])
        if result.rc != 0 and not spec.optional:
            session.gaps.append(f"{profile.name} command {spec.id} failed rc={result.rc}")
        commands.append({"id": spec.id, "rc": result.rc, "relpath": rel, "truncated": result.truncated})
    unit = _unit_detected(session, profile)
    resolved = _resolve_service(profile.ansible.service, family)
    manage = resolved is not None and (unit or bool(profile.ansible.packages.get(family)))
    return {
        "name": profile.name,
        "description": profile.description,
        "apply": profile.ansible.apply,
        "detected_by": hits,
        "unit_detected": unit,
        "manage_service": manage,
        "packages": {key: list(value) for key, value in profile.ansible.packages.items()},
        "service": None
        if resolved is None
        else {"name": resolved, "state": profile.ansible.service.state, "enabled": profile.ansible.service.enabled},
        "validate": [list(item.argv) for item in profile.ansible.validate],
        "note": profile.ansible.note,
        "files": files,
        "links": links,
        "commands": commands,
    }


def _resolve_service(spec: ServiceSpec | None, family: str) -> str | None:
    if spec is None:
        return None
    if spec.name:
        return spec.name
    return spec.names.get(family)


def _detect(session: Session, profile: Profile) -> list[str]:
    hits: list[str] = []
    for check in profile.detect:
        if check.kind == "path" and check.path and session.exists(check.path):
            hits.append(f"path:{check.path}")
        elif check.kind == "systemd" and check.unit and _unit_exists(session, check.unit):
            hits.append(f"systemd:{check.unit}")
        elif check.kind == "command_ok" and check.argv:
            result = session.run(list(check.argv))
            if result.rc == 0 and not result.timed_out:
                hits.append("command:" + check.argv[0])
    return hits


def _unit_exists(session: Session, unit: str) -> bool:
    for root in ("/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"):
        if session.exists(f"{root}/{unit}"):
            return True
    result = session.run(["systemctl", "cat", unit])
    return result.rc == 0 and not result.timed_out


def _unit_detected(session: Session, profile: Profile) -> bool:
    if profile.ansible.service is None:
        return False
    spec = profile.ansible.service
    names = [spec.name] if spec.name else list(spec.names.values())
    return any(name and _unit_exists(session, f"{name}.service") for name in names)


def _tree(session: Session, service: str, spec) -> tuple[list[dict], list[dict], bool]:
    if not session.exists(spec.path):
        if not spec.optional:
            session.gaps.append(f"missing {spec.path}")
            return [], [], True
        return [], [], False
    listed = session.paths_from(session.run(tree_find_argv(spec.path, spec.max_depth)), spec.path)
    if listed is None:
        return [], [], not spec.optional
    oversized = session.paths_from(
        session.run(oversized_find_argv(spec.path, spec.max_depth)), f"{spec.path} oversized"
    )
    if oversized:
        session.gaps.append(f"{spec.path} skipped oversized files: {', '.join(oversized[:10])}")
    files: list[dict] = []
    links: list[dict] = []
    for path in listed:
        base = path.rsplit("/", 1)[-1]
        if base in spec.exclude_names or any(base.endswith(suffix) for suffix in spec.exclude_suffixes):
            continue
        if path != spec.path and not path.startswith(spec.path.rstrip("/") + "/"):
            session.gaps.append(f"ignoring path outside {spec.path}: {path}")
            continue
        kind = session.run(["test", "-L", path])
        if kind.rc == 0:
            target = session.run(["readlink", "--", path])
            if target.rc != 0:
                session.gaps.append(f"could not read link {path}")
                continue
            link = target.stdout.decode("utf-8", "replace").strip()
            if _link_inside(spec.path, path, link):
                links.append({"path": path, "target": link})
            else:
                session.gaps.append(f"symlink escapes {spec.path}: {path} -> {link}")
            continue
        record = _one_file(session, service, path, optional=True)
        if record:
            files.append(record)
        if len(files) + len(links) > spec.max_files:
            session.gaps.append(f"{spec.path} has more than {spec.max_files} files")
            return [], [], True
    return files, links, False


def _glob(session: Session, service: str, spec) -> tuple[list[dict], bool]:
    if not session.exists(spec.root):
        if not spec.optional:
            session.gaps.append(f"missing {spec.root}")
            return [], True
        return [], False
    listed = session.paths_from(
        session.run(glob_find_argv(spec.root, spec.maxdepth, spec.names)), spec.root
    )
    if listed is None:
        return [], not spec.optional
    files = []
    incomplete = False
    for path in listed:
        if path != spec.root and not path.startswith(spec.root.rstrip("/") + "/"):
            session.gaps.append(f"ignoring path outside {spec.root}: {path}")
            continue
        record = _one_file(session, service, path, optional=True)
        if record:
            files.append(record)
        else:
            incomplete = True
    return files, incomplete


def _one_file(session: Session, service: str, path: str, optional: bool) -> dict | None:
    if not session.exists(path):
        if not optional:
            session.gaps.append(f"missing {path}")
        return None
    loaded = session.read_file(path)
    if loaded is None:
        return None
    data, mode, owner, group = loaded
    rel = "files" + path
    session.keep(rel, data)
    return {
        "path": path,
        "relpath": rel,
        "mode": mode,
        "owner": owner,
        "group": group,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "service": service,
    }


def _link_inside(root: str, link_path: str, target: str) -> bool:
    if "\n" in target or target.startswith("/"):
        resolved = target
    else:
        resolved = os.path.normpath(str(Path(link_path).parent / target))
    if ".." in target.split("/"):
        resolved = os.path.normpath(resolved)
    root = os.path.normpath(root)
    resolved = os.path.normpath(resolved)
    return resolved == root or resolved.startswith(root + "/")


def _security(session: Session) -> list[dict]:
    services = []
    ssh_files = []
    record = _one_file(session, "sshd", "/etc/ssh/sshd_config", optional=True)
    if record:
        ssh_files.append(record)
    if session.exists("/etc/ssh/sshd_config.d"):
        listed = session.paths_from(
            session.run(
                [
                    "find",
                    "-P",
                    "/etc/ssh/sshd_config.d",
                    "-maxdepth",
                    "1",
                    "-type",
                    "f",
                    "-name",
                    "*.conf",
                    "-size",
                    "-64k",
                    "-print0",
                ]
            ),
            "/etc/ssh/sshd_config.d",
        )
    else:
        listed = []
    if listed:
        for path in listed:
            record = _one_file(session, "sshd", path, optional=True)
            if record:
                ssh_files.append(record)
    if ssh_files:
        services.append(_review_service("sshd", "OpenSSH server configuration", ssh_files, []))
    sudo_files = []
    record = _one_file(session, "sudoers", "/etc/sudoers", optional=True)
    if record:
        sudo_files.append(record)
    if session.exists("/etc/sudoers.d"):
        listed = session.paths_from(
            session.run(
                [
                    "find",
                    "-P",
                    "/etc/sudoers.d",
                    "-maxdepth",
                    "1",
                    "-type",
                    "f",
                    "-size",
                    "-64k",
                    "-print0",
                ]
            ),
            "/etc/sudoers.d",
        )
        if listed:
            for path in listed:
                base = path.rsplit("/", 1)[-1]
                if base.startswith(".") or base.endswith("~") or base.endswith(".dpkg-dist"):
                    continue
                record = _one_file(session, "sudoers", path, optional=True)
                if record:
                    sudo_files.append(record)
    if sudo_files:
        services.append(_review_service("sudoers", "sudo policy", sudo_files, []))
    return services


def _review_service(name: str, description: str, files: list[dict], validate: list[list[str]]) -> dict:
    return {
        "name": name,
        "description": description,
        "apply": "review",
        "detected_by": [files[0]["path"]],
        "unit_detected": False,
        "manage_service": False,
        "packages": {},
        "service": None,
        "validate": validate,
        "note": "Review play only. Not applied by site.yml.",
        "files": files,
        "links": [],
        "commands": [],
    }


def _firewall(session: Session) -> dict:
    policy = None
    for candidate in ("/etc/fwng.yaml", "/etc/fwng/fwng.yaml", "/usr/local/etc/fwng.yaml"):
        record = _one_file(session, "firewall", candidate, optional=True)
        if record:
            policy = record
            break
    for argv, name in (
        (["nft", "list", "ruleset"], "nft-ruleset.txt"),
        (["iptables-save"], "iptables-save.txt"),
        (["ip6tables-save"], "ip6tables-save.txt"),
        (["firewall-cmd", "--list-all-zones"], "firewalld-zones.txt"),
    ):
        result = session.run(argv)
        if result.rc == 0 and result.stdout and not result.truncated:
            session.keep(f"evidence/firewall/{name}", result.stdout)
        elif result.rc not in {0, 127} and not result.timed_out:
            session.gaps.append(f"{argv[0]} exited {result.rc}; evidence not stored")
    return {
        "policy": policy,
        "replay": False,
        "reason": (
            "Live nftables and iptables output is evidence only. "
            "Replaying it restores stale Docker and k3s NAT. "
            "An fwng policy file, when present, is the deployable firewall."
        ),
    }


def _flush(out: Path, bundle: dict, blobs: dict[str, bytes]) -> None:
    if out.exists() and any(out.iterdir()):
        for child in sorted(out.iterdir(), reverse=True):
            if child.is_file():
                child.unlink()
            elif child.is_dir():
                _remove_tree(child)
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o700)
    for relpath, data in blobs.items():
        dest = out / relpath
        if not dest.resolve().is_relative_to(out.resolve()):
            raise InvestigateError(f"refusing to write outside the bundle: {relpath}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
    payload = (json.dumps(bundle, indent=2) + "\n").encode("utf-8")
    dest = out / "investigation.json"
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)


def _remove_tree(path: Path) -> None:
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            _remove_tree(child)
        else:
            child.unlink()
    path.rmdir()
