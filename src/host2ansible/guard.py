"""Read-only argv policy for commands investigate runs on a host.

Threats: a profile is local operator input, but it names commands that run
on the investigated machine. Shells, interpreters, and known mutating
commands are rejected before any transport starts. Unknown binaries are
allowed so a custom application can report its version. This does not prove
an unknown binary is read-only.
"""

from __future__ import annotations

import re

class ReadOnlyViolation(Exception):
    """The command would be refused before it is sent to a host."""


_SHELLS = {
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "ash",
    "busybox",
    "env",
    "timeout",
    "nice",
    "nohup",
    "stdbuf",
    "xargs",
}

_ALWAYS_DENY = {
    "rm",
    "mv",
    "cp",
    "install",
    "tee",
    "chmod",
    "chown",
    "chgrp",
    "touch",
    "mkdir",
    "rmdir",
    "ln",
    "mknod",
    "useradd",
    "usermod",
    "userdel",
    "groupadd",
    "groupmod",
    "groupdel",
    "passwd",
    "chpasswd",
    "apt",
    "apt-get",
    "dnf",
    "yum",
    "microdnf",
    "pacman",
    "zypper",
    "apk",
    "service",
    "reboot",
    "shutdown",
    "poweroff",
    "halt",
    "init",
    "telinit",
    "mkfs",
    "mkfs.ext4",
    "fdisk",
    "parted",
    "wipefs",
    "mount",
    "umount",
    "iptables-restore",
    "ip6tables-restore",
    "ufw",
    "ebtables",
    "arptables",
    "curl",
    "wget",
    "scp",
    "rsync",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "ssh",
    "sudo",
    "su",
    "doas",
    "pkexec",
    "perl",
    "ruby",
    "node",
    "php",
    "git",
    "mysql",
    "mariadb",
}

_SYSTEMCTL_READ = {
    "cat",
    "show",
    "status",
    "is-active",
    "is-enabled",
    "list-unit-files",
    "list-units",
}

_SYSTEMCTL_WRITE = {
    "start",
    "stop",
    "restart",
    "reload",
    "enable",
    "disable",
    "mask",
    "unmask",
    "edit",
    "isolate",
    "daemon-reload",
    "kill",
    "reset-failed",
}

_K8S_WRITE = {
    "apply",
    "delete",
    "create",
    "replace",
    "edit",
    "exec",
    "cp",
    "port-forward",
    "drain",
    "cordon",
    "uncordon",
    "taint",
    "scale",
    "rollout",
    "patch",
    "label",
    "annotate",
    "run",
    "attach",
}

_SHOW_SQL = re.compile(r"(?i)show\s+[a-z_][a-z0-9_]*\s*;?\s*\Z")
_VERSION_SQL = re.compile(r"(?i)select\s+version\s*\(\s*\)\s*;?\s*\Z")


def _base(argv0: str) -> str:
    return argv0.rsplit("/", 1)[-1]


def assert_read_only(argv: list[str]) -> None:
    if not argv or not all(isinstance(item, str) and item and "\x00" not in item for item in argv):
        raise ReadOnlyViolation("argv must be a list of non-empty strings")
    base = _base(argv[0])
    if base in _SHELLS or base.startswith("python"):
        raise ReadOnlyViolation(f"shell or interpreter is not allowed: {base}")
    if base == "systemctl":
        _systemctl(argv)
        return
    if base == "nft":
        _nft(argv)
        return
    if base in {"iptables", "ip6tables"}:
        _iptables(argv)
        return
    if base in {"iptables-save", "ip6tables-save"}:
        if len(argv) != 1:
            raise ReadOnlyViolation(f"{base} takes no arguments")
        return
    if base == "firewall-cmd":
        _firewall_cmd(argv)
        return
    if base == "dd":
        _dd(argv)
        return
    if base == "ip":
        _ip(argv)
        return
    if base in {"docker", "podman"}:
        _docker(argv)
        return
    if base in {"k3s", "kubectl", "crictl"}:
        _k8s(argv)
        return
    if base == "psql":
        _psql(argv)
        return
    if base == "postconf":
        _postconf(argv)
        return
    if base in _ALWAYS_DENY:
        raise ReadOnlyViolation(f"mutating command is not allowed: {base}")


def _systemctl(argv: list[str]) -> None:
    if any(item in _SYSTEMCTL_WRITE for item in argv[1:]):
        raise ReadOnlyViolation("systemctl write is not allowed")
    if len(argv) < 2 or argv[1] not in _SYSTEMCTL_READ:
        raise ReadOnlyViolation("systemctl is limited to read-only subcommands")


def _nft(argv: list[str]) -> None:
    if argv[1:] in (["list", "ruleset"], ["--version"], ["-v"]):
        return
    raise ReadOnlyViolation("nft is limited to: nft list ruleset")


def _iptables(argv: list[str]) -> None:
    if argv[1:] in (["-S"], ["--list-rules"], ["--version"], ["-V"]):
        return
    raise ReadOnlyViolation("iptables is limited to -S")


def _firewall_cmd(argv: list[str]) -> None:
    write_prefixes = (
        "--add",
        "--remove",
        "--change",
        "--set",
        "--new",
        "--delete",
        "--permanent",
        "--reload",
        "--complete-reload",
        "--runtime-to-permanent",
    )
    for item in argv[1:]:
        if item.startswith(write_prefixes):
            raise ReadOnlyViolation(f"firewall-cmd {item} is not allowed")
    if not any(
        item.startswith("--list") or item.startswith("--get-") or item in {"--state", "--version"}
        for item in argv[1:]
    ):
        raise ReadOnlyViolation("firewall-cmd is limited to list and get queries")


def _dd(argv: list[str]) -> None:
    opts = argv[1:]
    if any(item.startswith("of=") for item in opts):
        raise ReadOnlyViolation("dd of= is not allowed")
    if not any(item.startswith("if=") for item in opts):
        raise ReadOnlyViolation("dd requires if= and forbids of=")


def _ip(argv: list[str]) -> None:
    bad = {"add", "del", "delete", "set", "change", "replace", "flush", "monitor"}
    if any(item in bad for item in argv[1:]):
        raise ReadOnlyViolation("ip mutation is not allowed")
    if "addr" not in argv[1:] and "address" not in argv[1:]:
        raise ReadOnlyViolation("ip is limited to addr show")


def _docker(argv: list[str]) -> None:
    if len(argv) < 2:
        raise ReadOnlyViolation("docker needs a read-only subcommand")
    sub = argv[1]
    if sub == "compose":
        if len(argv) >= 3 and argv[2] in {"ls", "version"}:
            return
        raise ReadOnlyViolation("docker compose is limited to ls and version")
    if sub in {"version", "info", "ps", "images"}:
        return
    raise ReadOnlyViolation(f"docker {sub} is not allowed")


def _k8s(argv: list[str]) -> None:
    if "secret" in argv[1:] or "secrets" in argv[1:]:
        raise ReadOnlyViolation("refusing to read Kubernetes secrets")
    if any(item in _K8S_WRITE for item in argv[1:]):
        raise ReadOnlyViolation("Kubernetes write command is not allowed")
    if "--version" in argv[1:]:
        return
    if any(item in {"get", "describe", "version", "api-resources"} for item in argv[1:]):
        return
    raise ReadOnlyViolation("Kubernetes command is not a read query")


def _psql(argv: list[str]) -> None:
    if argv[1:] in (["--version"], ["-V"]):
        return
    flag = "-c" if "-c" in argv else "--command" if "--command" in argv else ""
    if not flag:
        raise ReadOnlyViolation("psql is limited to --version or one SHOW query")
    idx = argv.index(flag)
    if idx + 1 >= len(argv):
        raise ReadOnlyViolation("psql query is missing")
    statement = argv[idx + 1].strip()
    if _SHOW_SQL.fullmatch(statement) or _VERSION_SQL.fullmatch(statement):
        return
    raise ReadOnlyViolation("psql query is not a single SHOW or SELECT version()")


def _postconf(argv: list[str]) -> None:
    allowed = {"-n", "-d", "-p", "-h", "-v", "--version"}
    for item in argv[1:]:
        if item in {"-e", "-#", "-X", "-R"} or (item.startswith("-") and item not in allowed):
            raise ReadOnlyViolation(f"postconf {item} is not allowed")
