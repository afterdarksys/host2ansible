"""In-memory Linux host for investigate tests."""

from __future__ import annotations

import fnmatch

from host2ansible.guard import assert_read_only
from host2ansible.transport import CommandResult


class MapTransport:
    def __init__(self, files: dict[str, bytes], links: dict[str, str] | None = None, address: str = "203.0.113.9"):
        self.files = files
        self.links = links or {}
        self.address = address
        self.label = "map"
        self.calls: list[list[str]] = []

    def run(self, argv: list[str], timeout: float) -> CommandResult:
        assert_read_only(argv)
        self.calls.append(list(argv))
        base = argv[0].rsplit("/", 1)[-1].replace("-", "_")
        handler = getattr(self, f"do_{base}", None)
        if handler is None:
            return CommandResult(argv, 127, b"", b"not found\n")
        return handler(argv)

    def do_uname(self, argv: list[str]) -> CommandResult:
        if argv[1:] == ["-s"]:
            return CommandResult(argv, 0, b"Linux\n", b"")
        return CommandResult(argv, 0, b"Linux fixture 6.1\n", b"")

    def do_test(self, argv: list[str]) -> CommandResult:
        flag, path = argv[1], argv[2]
        if flag == "-e":
            ok = path in self.files or path in self.links or self._is_dir(path)
        elif flag == "-L":
            ok = path in self.links
        else:
            ok = False
        return CommandResult(argv, 0 if ok else 1, b"", b"")

    def do_stat(self, argv: list[str]) -> CommandResult:
        path = argv[-1]
        if path not in self.files:
            return CommandResult(argv, 1, b"", b"missing\n")
        return CommandResult(argv, 0, f"{len(self.files[path])} 640 root root\n".encode(), b"")

    def do_head(self, argv: list[str]) -> CommandResult:
        count = int(argv[argv.index("-c") + 1])
        path = argv[-1]
        if path not in self.files:
            return CommandResult(argv, 1, b"", b"missing\n")
        return CommandResult(argv, 0, self.files[path][:count], b"")

    def do_readlink(self, argv: list[str]) -> CommandResult:
        path = argv[-1]
        if path not in self.links:
            return CommandResult(argv, 1, b"", b"")
        return CommandResult(argv, 0, (self.links[path] + "\n").encode(), b"")

    def do_ip(self, argv: list[str]) -> CommandResult:
        if "-4" in argv:
            line = f"2: eth0    inet {self.address}/24 brd 203.0.113.255 scope global eth0\n"
            return CommandResult(argv, 0, line.encode(), b"")
        return CommandResult(argv, 0, b"", b"")

    def do_find(self, argv: list[str]) -> CommandResult:
        root = argv[2]
        if not self._is_dir(root) and root not in self.files:
            return CommandResult(argv, 1, b"", b"missing\n")
        maxdepth = int(argv[argv.index("-maxdepth") + 1])
        names = [argv[index + 1] for index, item in enumerate(argv) if item == "-name"]
        want_files = "f" in argv
        want_links = "l" in argv
        oversized = "+511k" in argv
        paths: list[str] = []
        if oversized:
            candidates = [path for path, data in self.files.items() if len(data) >= 512 * 1024]
        else:
            candidates = []
            if want_files:
                candidates.extend(self.files)
            if want_links:
                candidates.extend(self.links)
        limit = 64 * 1024 if "-64k" in argv else 512 * 1024
        for path in sorted(set(candidates)):
            if not (path == root or path.startswith(root.rstrip("/") + "/")):
                continue
            rel = path[len(root.rstrip("/")) + 1 :]
            depth = rel.count("/") + 1
            if depth > maxdepth:
                continue
            base = path.rsplit("/", 1)[-1]
            if names and not any(fnmatch.fnmatch(base, pattern) for pattern in names):
                continue
            if not oversized and path in self.files and len(self.files[path]) >= limit:
                continue
            paths.append(path)
        payload = b"\0".join(path.encode() for path in paths)
        if payload:
            payload += b"\0"
        return CommandResult(argv, 0, payload, b"")

    def _is_dir(self, path: str) -> bool:
        prefix = path.rstrip("/") + "/"
        return any(item.startswith(prefix) for item in list(self.files) + list(self.links))
