"""host2ansible investigate (read-only) and host2ansible build (local)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from host2ansible import __version__
from host2ansible.guard import ReadOnlyViolation
from host2ansible.investigate import InvestigateError, investigate
from host2ansible.paths import PathDenied
from host2ansible.profiles import ProfileError, load_many
from host2ansible.render import BuildError, build
from host2ansible.transport import DockerTransport, LocalTransport, SshTransport, TransportError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="host2ansible")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("investigate", help="read a host and write a bundle; does not modify the host")
    inv.add_argument("--transport", choices=("docker", "ssh", "local"), required=True)
    inv.add_argument("--container", help="docker container name")
    inv.add_argument("--destination", help="ssh destination, user@host")
    inv.add_argument("--identity", help="ssh identity file")
    inv.add_argument(
        "--accept-new-host-key",
        action="store_true",
        help="opt in to SSH accept-new; default is StrictHostKeyChecking=yes",
    )
    inv.add_argument("--out", type=Path, default=Path("investigations"))
    inv.add_argument("--profile", type=Path, action="append", default=[])
    inv.add_argument("--profile-dir", type=Path, action="append", default=[])
    inv.add_argument("--timeout", type=float, default=20)
    inv.add_argument("--force", action="store_true")

    built = sub.add_parser("build", help="render Ansible from a bundle; does not contact a host")
    built.add_argument("--from", dest="source", type=Path, required=True)
    built.add_argument("--force", action="store_true")

    args = parser.parse_args(argv)
    try:
        if args.command == "investigate":
            return _investigate(args)
        hits = build(args.source, args.force)
        print(f"wrote {args.source / 'ansible'}")
        print(f"secrets to fill: {len(hits)}")
        print(f"next: python3 {args.source / 'run_converted.py'} test")
        return 0
    except (InvestigateError, ProfileError, BuildError, TransportError, ReadOnlyViolation, PathDenied) as exc:
        print(f"host2ansible: {exc}", file=sys.stderr)
        return 1


def _investigate(args) -> int:
    if args.timeout <= 0 or args.timeout > 120:
        raise InvestigateError("--timeout must be between 0 and 120 seconds")
    profiles = load_many(args.profile, args.profile_dir)
    if args.transport == "docker":
        if not args.container:
            raise InvestigateError("docker transport requires --container")
        transport = DockerTransport(args.container)
    elif args.transport == "ssh":
        if not args.destination:
            raise InvestigateError("ssh transport requires --destination")
        transport = SshTransport(args.destination, args.identity, args.accept_new_host_key)
    else:
        transport = LocalTransport()
    out = investigate(transport, profiles, args.out, args.timeout, args.force)
    print(f"wrote {out}")
    print("target was not modified")
    print(f"next: host2ansible build --from {out}")
    return 0
