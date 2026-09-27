"""Run generated Ansible. This is the deploy machine, not the investigated one.

Threats: execute and validate open a connection. An inventory whose
ansible_host is an address collected from the source host is refused unless
--allow-source-address is passed. Syntax-check does not connect.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

_HOST = re.compile(r"ansible_host=(\S+)")


class RunnerError(Exception):
    """The generated play was not started."""


def main(bundle_dir: Path, argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_converted.py")
    sub = parser.add_subparsers(dest="command", required=True)
    test = sub.add_parser("test", help="syntax-check, and optionally ansible --check")
    test.add_argument("--inventory")
    test.add_argument("--allow-source-address", action="store_true")
    execute = sub.add_parser("execute", help="apply site.yml to a new host")
    execute.add_argument("--inventory", required=True)
    execute.add_argument("--yes", action="store_true")
    execute.add_argument("--include-review", action="store_true")
    execute.add_argument("--allow-source-address", action="store_true")
    validate = sub.add_parser("validate", help="run collected read-only checks on the new host")
    validate.add_argument("--inventory", required=True)
    validate.add_argument("--allow-source-address", action="store_true")
    args = parser.parse_args(argv)
    try:
        return _run(bundle_dir, args)
    except RunnerError as exc:
        print(f"host2ansible: {exc}", file=sys.stderr)
        return 1


def _run(bundle_dir: Path, args) -> int:
    bundle = json.loads((bundle_dir / "investigation.json").read_text(encoding="utf-8"))
    ansible = bundle_dir / "ansible"
    if not (ansible / "site.yml").is_file():
        raise RunnerError("ansible/site.yml is missing; run host2ansible build")
    if args.command == "test":
        rc = _ansible(ansible, ["--syntax-check", "-i", "inventory.example.ini", "site.yml"])
        if rc:
            return rc
        rc = _ansible(ansible, ["--syntax-check", "-i", "inventory.example.ini", "site-review.yml"])
        if rc or not args.inventory:
            return rc
        _refuse_source(bundle, Path(args.inventory), args.allow_source_address)
        return _ansible(ansible, ["--check", "-i", args.inventory, "site.yml"])
    inventory = Path(args.inventory)
    if inventory.name == "inventory.example.ini":
        raise RunnerError("write a real inventory; inventory.example.ini is not a target")
    _refuse_source(bundle, inventory, args.allow_source_address)
    if args.command == "execute":
        if not args.yes:
            raise RunnerError("execute requires --yes")
        plays = ["site.yml"]
        if args.include_review:
            plays.append("site-review.yml")
        rc = 0
        for play in plays:
            rc = _ansible(ansible, ["-i", str(inventory), play])
            if rc:
                return rc
        return 0
    return _ansible(ansible, ["-i", str(inventory), "validate.yml"])


def _refuse_source(bundle: dict, inventory: Path, allow: bool) -> None:
    if allow:
        return
    if not inventory.is_file():
        raise RunnerError(f"inventory not found: {inventory}")
    text = inventory.read_text(encoding="utf-8")
    wanted = set(_HOST.findall(text))
    source = set(bundle.get("source", {}).get("addresses") or [])
    overlap = wanted & source
    if overlap:
        raise RunnerError(
            "refusing to contact an address collected from the investigated host: "
            + ", ".join(sorted(overlap))
        )


def _ansible(ansible: Path, args: list[str]) -> int:
    proc = subprocess.run(["ansible-playbook", *args], cwd=ansible)
    return proc.returncode
