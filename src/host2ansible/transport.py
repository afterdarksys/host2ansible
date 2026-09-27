"""How investigate reaches a machine. The remote argv is already policy-checked."""

from __future__ import annotations

import re
import os
import selectors
import signal
import time
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


def run_local(cmd: list[str], timeout: float, remote_argv: list[str], *, cwd=None) -> CommandResult:
    """Bound both streams while reading; kill descendants on timeout or overflow."""
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True, cwd=cwd)
    except OSError as exc:
        raise TransportError(str(exc)) from exc
    buffers = [bytearray(), bytearray()]
    deadline = time.monotonic() + timeout
    timed_out = truncated = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ, 0)
            selector.register(proc.stderr, selectors.EVENT_READ, 1)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.data]
                    available = MAX_COMMAND_BYTES - len(buffer)
                    buffer.extend(chunk[:available])
                    if len(chunk) > available:
                        truncated = True
                        break
                if truncated:
                    break
            if not timed_out and not truncated:
                try:
                    proc.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    timed_out = True
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        proc.stdout.close()
        proc.stderr.close()
    return CommandResult(remote_argv, 124 if timed_out else 125 if truncated else proc.returncode,
                         bytes(buffers[0]), bytes(buffers[1]), timed_out=timed_out, truncated=truncated)


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
