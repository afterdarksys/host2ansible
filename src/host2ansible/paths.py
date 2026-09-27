"""Which remote paths investigate may read.

Threats: refuses shadow files, SSH host private keys, home directories, and
the data directories Docker, k3s, and Postgres rewrite continuously. A custom
profile cannot point a tree walk at those paths. A narrow glob may name
Postgres config files under /var/lib/pgsql and nothing else there.
"""

from __future__ import annotations

PG_CONFIG_NAMES = frozenset(
    {"postgresql.conf", "pg_hba.conf", "pg_ident.conf", "postgresql.auto.conf"}
)

_DENIED_TREE_EXACT = frozenset(
    {
        "/",
        "/home",
        "/root",
        "/var",
        "/var/lib",
        "/etc",
        "/usr",
        "/opt",
        "/etc/ssh",
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/tmp",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
    }
)

# Prefix match is on a directory boundary. "/etc/ssh" denies "/etc/ssh/keys"
# but a later allowlist re-opens sshd_config only.
_DENIED_PREFIXES = (
    "/home",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/tmp",
    "/var/log",
    "/var/lib/docker",
    "/var/lib/containerd",
    "/var/lib/rancher",
    "/var/lib/kubelet",
    "/var/lib/kube",
    "/var/lib/postgresql",
    "/var/lib/pgsql",
    "/etc/ssh",
    "/usr/bin",
    "/usr/lib",
    "/usr/lib64",
    "/usr/share",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
)

_NEVER_READ = frozenset(
    {
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/passwd-",
        "/etc/shadow-",
        "/etc/subuid",
        "/etc/subgid",
        "/etc/security/opasswd",
    }
)

_SSH_ALLOW_EXACT = frozenset({"/etc/ssh/sshd_config"})


class PathDenied(Exception):
    """The path is outside the read policy."""


def normalize(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
        raise PathDenied(f"path must be absolute: {path!r}")
    raw = path.split("/")
    if ".." in raw or "." in raw[1:]:
        raise PathDenied(f"path must not contain '.' or '..': {path}")
    parts = [part for part in raw if part]
    cleaned = "/" + "/".join(parts) if parts else "/"
    if len(cleaned) > 300:
        raise PathDenied("path is too long")
    return cleaned


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def _denied_prefix(path: str) -> str | None:
    for prefix in _DENIED_PREFIXES:
        if _under(path, prefix):
            return prefix
    return None


def assert_detect_path(path: str) -> str:
    """Existence checks may name a path we will not walk."""
    path = normalize(path)
    if path in _NEVER_READ:
        raise PathDenied(f"refusing to touch {path}")
    base = path.rsplit("/", 1)[-1]
    if base.startswith("ssh_host_"):
        raise PathDenied(f"refusing SSH host key {path}")
    return path


def assert_tree(path: str) -> str:
    path = normalize(path)
    if path in _DENIED_TREE_EXACT:
        raise PathDenied(f"refusing to walk {path}")
    if path in _NEVER_READ or _denied_prefix(path):
        raise PathDenied(f"refusing to walk {path}")
    return path


def assert_file(path: str) -> str:
    path = normalize(path)
    if path in _NEVER_READ:
        raise PathDenied(f"refusing to read {path}")
    base = path.rsplit("/", 1)[-1]
    if base.startswith("ssh_host_"):
        raise PathDenied(f"refusing SSH host key {path}")
    if path in _SSH_ALLOW_EXACT or (
        path.startswith("/etc/ssh/sshd_config.d/") and path.endswith(".conf") and path.count("/") == 4
    ):
        return path
    if path == "/etc/sudoers" or (
        path.startswith("/etc/sudoers.d/") and path.count("/") == 3 and base not in {".", ".."}
    ):
        return path
    denied = _denied_prefix(path)
    if denied:
        raise PathDenied(f"refusing to read {path}")
    return path


def assert_glob(root: str, names: tuple[str, ...]) -> str:
    root = normalize(root)
    if root in _DENIED_TREE_EXACT or root in _NEVER_READ:
        raise PathDenied(f"refusing to glob {root}")
    if not names:
        raise PathDenied("glob needs explicit file names")
    for name in names:
        if (
            not name
            or name in {".", "..", "*"}
            or "/" in name
            or name.startswith(".")
            or any(char in name for char in "*?[]")
        ):
            raise PathDenied(f"glob name must be one explicit file name: {name!r}")
    if _denied_prefix(root):
        if _under(root, "/var/lib/pgsql") and set(names) <= PG_CONFIG_NAMES:
            return root
        raise PathDenied(f"refusing to glob {root}")
    return root
