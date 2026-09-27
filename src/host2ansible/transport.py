"""How investigate reaches a machine. The remote argv is already policy-checked."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

from host2ansible.guard import assert_read_only

MAX_COMMAND_BYTES = 1_000_000

_DEST = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:@-]{0,200}\Z")
_CONTAINER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,80}\Z")


class TransportError(Exception):
    """The local side could not start the read."""


@dataclass
class CommandResult:
    argv: list[str]
    rc: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    truncated: bool = False


def _clip(data: bytes | None) -> tuple[bytes, bool]:
    blob = data or b""
    if len(blob) > MAX_COMMAND_BYTES:
        return blob[:MAX_COMMAND_BYTES], True
    return blob, False


def run_local(cmd: list[str], timeout: float, remote_argv: list[str]) -> CommandResult:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        stdout, truncated = _clip(exc.stdout if isinstance(exc.stdout, bytes) else None)
        stderr, _ = _clip(exc.stderr if isinstance(exc.stderr, bytes) else None)
        return CommandResult(remote_argv, 124, stdout, stderr, timed_out=True, truncated=truncated)
    except OSError as exc:
        raise TransportError(str(exc)) from exc
    stdout, truncated = _clip(proc.stdout)
    stderr, err_truncated = _clip(proc.stderr)
    return CommandResult(
        remote_argv,
        proc.returncode,
        stdout,
        stderr,
        truncated=truncated or err_truncated,
    )


class LocalTransport:
    label = "local"

    def run(self, argv: list[str], timeout: float) -> CommandResult:
        assert_read_only(argv)
        return run_local(argv, timeout, argv)


class DockerTransport:
    def __init__(self, container: str):
        if not _CONTAINER.fullmatch(container):
            raise TransportError(f"invalid container name: {container!r}")
        self.container = container
        self.label = f"docker:{container}"
        state = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container],
            capture_output=True,
            timeout=30,
        )
        if state.returncode != 0 or state.stdout.strip() != b"true":
            detail = state.stderr.decode("utf-8", "replace").strip()
            raise TransportError(f"container {container} is not running{': ' + detail if detail else ''}")

    def run(self, argv: list[str], timeout: float) -> CommandResult:
        assert_read_only(argv)
        return run_local(["docker", "exec", "-i", self.container, *argv], timeout, argv)


class SshTransport:
    def __init__(self, destination: str, identity: str | None, accept_new: bool):
        if not _DEST.fullmatch(destination) or any(char in destination for char in " \t;|&<>`$\\"):
            raise TransportError(f"invalid ssh destination: {destination!r}")
        self.destination = destination
        self.identity = identity
        self.accept_new = accept_new
        self.label = f"ssh:{destination}"

    def run(self, argv: list[str], timeout: float) -> CommandResult:
        assert_read_only(argv)
        import shlex

        checking = "accept-new" if self.accept_new else "yes"
        cmd = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            f"StrictHostKeyChecking={checking}",
            "-o",
            "ConnectTimeout=10",
        ]
        if self.identity:
            cmd.extend(["-i", self.identity])
        cmd.extend([self.destination, shlex.join(argv)])
        return run_local(cmd, timeout + 15, argv)
