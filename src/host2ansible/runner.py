"""Run generated Ansible. This is the deploy machine, not the investigated one.

Threats: execute and validate open a connection. An inventory whose
ansible_host is an address collected from the source host is refused unless
--allow-source-address is passed. Syntax-check does not connect.
"""

from __future__ import annotations

import argparse
import json
import ipaddress
import socket
import tempfile
from contextlib import contextmanager
import subprocess
import sys
from pathlib import Path

from host2ansible.transport import run_local, TransportError


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
    except (RunnerError, TransportError, OSError, ValueError) as exc:
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
        with _checked_inventory(bundle, ansible, args.inventory, args.allow_source_address) as inventory:
            return _ansible(ansible, ["--check", "-i", str(inventory), "site.yml"])
    inventory = Path(args.inventory).resolve(strict=True)
    if inventory.name == "inventory.example.ini":
        raise RunnerError("write a real inventory; inventory.example.ini is not a target")
    if args.command == "execute" and not args.yes:
        raise RunnerError("execute requires --yes")
    with _checked_inventory(bundle, ansible, inventory, args.allow_source_address) as checked:
        plays = ["validate.yml"] if args.command == "validate" else ["site.yml"]
        if args.command == "execute" and args.include_review:
            plays.append("site-review.yml")
        for play in plays:
            rc = _ansible(ansible, ["-i", str(checked), play])
            if rc:
                return rc
    return 0


def _ip(value):
    address = ipaddress.ip_address(value.strip("[]").split("%", 1)[0])
    return str(address.ipv4_mapped or address) if isinstance(address, ipaddress.IPv6Address) else str(address)


def _resolve_host(value):
    if not isinstance(value, str) or not value or any(c in value for c in "{} \t\n"):
        raise RunnerError("inventory host must resolve to a concrete address")
    try:
        return {_ip(value)}
    except ValueError:
        try:
            return {_ip(row[4][0]) for row in socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)}
        except socket.gaierror as exc:
            raise RunnerError(f"cannot resolve inventory host: {value}") from exc


def _refuse_source(bundle: dict, inventory: Path, allow: bool, ansible: Path | None = None) -> dict:
    inventory = inventory.resolve(strict=True)
    ansible = (ansible or inventory.parent).resolve()
    cmd = ["ansible-inventory", "-i", str(inventory), "--list", "--playbook-dir", str(ansible)]
    result = run_local(cmd, 30, cmd, cwd=ansible)
    if result.rc != 0 or result.truncated or result.timed_out:
        raise RunnerError("could not resolve inventory with ansible-inventory")
    try:
        value = json.loads(result.stdout)
        hostvars = value["_meta"]["hostvars"]
        if not isinstance(hostvars, dict):
            raise ValueError()
        hosts, visiting = set(), set()
        def collect(group):
            if group in visiting:
                raise ValueError("cyclic inventory groups")
            visiting.add(group)
            entry = value[group]
            hosts.update(entry.get("hosts", []))
            for child in entry.get("children", []):
                collect(child)
            visiting.remove(group)
        collect("converted")
        if not hosts or any(not isinstance(host, str) for host in hosts):
            raise ValueError()
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise RunnerError("inventory must resolve to a nonempty converted group") from exc
    if allow:
        return value
    source = {_ip(address) for address in bundle.get("source", {}).get("addresses", [])}
    if not source:
        raise RunnerError("source addresses were not collected; cannot establish target separation")
    for host in sorted(hosts):
        variables = hostvars.setdefault(host, {})
        if variables.get("ansible_connection", "ssh") not in ("ssh", "paramiko", "paramiko_ssh"):
            raise RunnerError("source protection requires an SSH inventory connection")
        # Connection redirection cannot be inferred from an address comparison.
        for key in ("ansible_ssh_common_args", "ansible_ssh_extra_args", "ansible_ssh_args", "ansible_ssh_executable"):
            if variables.get(key):
                raise RunnerError(f"source protection cannot verify inventory override {key}")
        destination = variables.get("ansible_host", variables.get("ansible_ssh_host", host))
        addresses = _resolve_host(destination)
        if not addresses or addresses & source:
            raise RunnerError("refusing to contact an address collected from the investigated host: " + str(destination))
        # Freeze DNS and inventory-plugin output for the subsequent playbook.
        address = sorted(addresses, key=lambda x: (":" in x, x))[0]
        variables["ansible_host"] = variables["ansible_ssh_host"] = address
    return value


@contextmanager
def _checked_inventory(bundle, ansible, path, allow):
    # Resolve relative paths before switching cwd. Execute only the checked snapshot.
    value = _refuse_source(bundle, Path(path).resolve(strict=True), allow, ansible)
    with tempfile.TemporaryDirectory(prefix=".h2a-inventory-", dir=ansible) as directory:
        snapshot = Path(directory) / "inventory.json"
        # --list is dynamic-inventory JSON; materialize static YAML/JSON shape
        # so Ansible does not re-run the original plugin or misparse hosts lists.
        hostvars = value["_meta"]["hostvars"]
        static = {}
        for name, group in value.items():
            if name == "_meta":
                continue
            static[name] = {"hosts": {host: hostvars.get(host, {}) for host in group.get("hosts", [])},
                            "children": {child: {} for child in group.get("children", [])},
                            "vars": group.get("vars", {})}
        snapshot.write_text(json.dumps(static), encoding="utf-8")
        snapshot.chmod(0o600)
        yield snapshot.resolve()


def _ansible(ansible: Path, args: list[str]) -> int:
    proc = subprocess.run(["ansible-playbook", *args], cwd=ansible)
    return proc.returncode
