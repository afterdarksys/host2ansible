"""Turn an investigation bundle into Ansible. This never contacts a host."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import yaml

from host2ansible.redact import SecretHit, redact_text, to_template

class BuildError(Exception):
    """The bundle could not be rendered."""


def build(bundle_dir: Path, force: bool) -> list[SecretHit]:
    bundle_path = bundle_dir / "investigation.json"
    if not bundle_path.is_file():
        raise BuildError(f"no investigation.json in {bundle_dir}")
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    if bundle.get("schema") != 1:
        raise BuildError("unsupported investigation schema")
    ansible = bundle_dir / "ansible"
    if ansible.exists() and any(ansible.iterdir()) and not force:
        raise BuildError(f"{ansible} already exists; pass --force")
    if ansible.exists():
        shutil.rmtree(ansible)
    ansible.mkdir()
    hits: list[SecretHit] = []
    counter = 1
    auto = [item for item in bundle["services"] if item["apply"] == "auto"]
    review = [item for item in bundle["services"] if item["apply"] == "review"]
    for service in auto + review:
        found, counter = _role(ansible, bundle_dir, service, bundle["os"]["family"], counter)
        hits.extend(found)
    found, counter = _firewall_role(ansible, bundle_dir, bundle["firewall"], counter)
    hits.extend(found)
    _base_role(ansible)
    _plays(ansible, bundle, auto, review, hits)
    _vars(ansible, bundle, hits)
    _meta(ansible, bundle)
    (bundle_dir / "run_converted.py").write_text(_SHIM, encoding="utf-8")
    (bundle_dir / "run_converted.py").chmod(0o700)
    (bundle_dir / "README.md").write_text(_readme(bundle, hits), encoding="utf-8")
    return hits


def _role(
    ansible: Path, bundle_dir: Path, service: dict, family: str, counter: int
) -> tuple[list[SecretHit], int]:
    role = ansible / "roles" / service["name"]
    tasks: list[dict] = []
    handlers: list[dict] = []
    hits: list[SecretHit] = []
    if service.get("note"):
        tasks.append({"name": f"Note for {service['name']}", "ansible.builtin.debug": {"msg": service["note"]}})
    packages = service.get("packages") or {}
    chosen = list(packages.get(family) or [])
    if family not in {"debian", "redhat"} and any(packages.values()):
        tasks.append(
            {
                "name": f"Refuse to guess {service['name']} packages",
                "ansible.builtin.fail": {
                    "msg": f"OS family is {family}. Set package names for {service['name']} before deploying."
                },
            }
        )
    elif chosen:
        tasks.append(
            {
                "name": f"Install {service['name']} packages",
                "ansible.builtin.package": {"name": "{{ item }}", "state": "present"},
                "loop": chosen,
            }
        )
    manage = bool(service.get("manage_service"))
    file_tasks, file_hits, counter = _files(role, bundle_dir, service, counter, notify=manage)
    hits.extend(file_hits)
    parents = sorted({str(Path(item["path"]).parent) for item in service["files"]}, key=lambda item: (item.count("/"), item))
    for parent in parents:
        if parent in {"/", ""}:
            continue
        tasks.append(
            {
                "name": f"Create {parent}",
                "ansible.builtin.file": {"path": parent, "state": "directory", "mode": "0755"},
            }
        )
    tasks.extend(file_tasks)
    for link in service.get("links") or []:
        tasks.append(
            {
                "name": f"Link {link['path']}",
                "ansible.builtin.file": {"src": link["target"], "dest": link["path"], "state": "link"},
            }
        )
    unit = (service.get("service") or {}).get("name")
    if manage and unit:
        tasks.append(
            {
                "name": f"Enable {unit}",
                "ansible.builtin.systemd": {
                    "name": unit,
                    "state": service["service"]["state"],
                    "enabled": service["service"]["enabled"],
                },
            }
        )
        handlers.append(
            {
                "name": f"restart {unit}",
                "ansible.builtin.systemd": {"name": unit, "state": "restarted"},
            }
        )
    if not tasks:
        tasks.append({"name": f"{service['name']} had no deployable files", "ansible.builtin.debug": {"msg": "nothing to copy"}})
    _write_yaml(role / "tasks" / "main.yml", tasks)
    if handlers:
        _write_yaml(role / "handlers" / "main.yml", handlers)
    return hits, counter


def _files(
    role: Path, bundle_dir: Path, service: dict, counter: int, notify: bool
) -> tuple[list[dict], list[SecretHit], int]:
    tasks = []
    hits: list[SecretHit] = []
    unit = (service.get("service") or {}).get("name")
    for record in service["files"]:
        source = bundle_dir / record["relpath"]
        data = source.read_bytes()
        if b"\x00" in data:
            tasks.append(
                {
                    "name": f"Skip binary {record['path']}",
                    "ansible.builtin.debug": {"msg": f"{record['path']} is binary and was not rendered"},
                }
            )
            continue
        text = data.decode("utf-8")
        tokenized, found = redact_text(text, service["name"], record["path"], start=counter)
        counter += len(found)
        hits.extend(found)
        rel = record["path"].lstrip("/")
        mode = record.get("mode") or "0644"
        task: dict
        if found:
            dest = role / "templates" / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(to_template(tokenized, found), encoding="utf-8")
            body = {"src": rel, "dest": record["path"], "mode": mode}
            task = {"name": f"Template {record['path']}", "ansible.builtin.template": body}
        else:
            dest = role / "files" / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            body = {"src": rel, "dest": record["path"], "mode": mode}
            if record["path"] == "/etc/sudoers":
                body["validate"] = "/usr/sbin/visudo -cf %s"
            if record["path"] == "/etc/ssh/sshd_config":
                body["validate"] = "/usr/sbin/sshd -t -f %s"
            task = {"name": f"Copy {record['path']}", "ansible.builtin.copy": body}
        if notify and unit:
            task["notify"] = f"restart {unit}"
        tasks.append(task)
    return tasks, hits, counter


def _firewall_role(
    ansible: Path, bundle_dir: Path, firewall: dict, counter: int
) -> tuple[list[SecretHit], int]:
    tasks: list[dict] = [
        {
            "name": "Live firewall snapshots are not applied",
            "ansible.builtin.debug": {"msg": firewall["reason"]},
        }
    ]
    hits: list[SecretHit] = []
    policy = firewall.get("policy")
    if policy:
        data = (bundle_dir / policy["relpath"]).read_bytes()
        if looks_private(data):
            raise BuildError("fwng policy looks like a private key")
        text = data.decode("utf-8")
        tokenized, hits = redact_text(text, "firewall", policy["path"], start=counter)
        counter += len(hits)
        if hits:
            dest = ansible / "roles" / "firewall" / "templates" / "fwng.yaml.j2"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(to_template(tokenized, hits), encoding="utf-8")
            install = {
                "name": "Install fwng policy",
                "ansible.builtin.template": {"src": "fwng.yaml.j2", "dest": "/etc/fwng.yaml", "mode": "0640"},
            }
        else:
            dest = ansible / "roles" / "firewall" / "files" / "fwng.yaml"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            install = {
                "name": "Install fwng policy",
                "ansible.builtin.copy": {"src": "fwng.yaml", "dest": "/etc/fwng.yaml", "mode": "0640"},
            }
        tasks.extend(
            [
                install,
                {
                    "name": "Validate fwng policy when fwng is installed",
                    "ansible.builtin.command": {"argv": ["fwng", "validate", "--config", "/etc/fwng.yaml"]},
                    "changed_when": False,
                    "register": "h2a_fwng_validate",
                    "failed_when": "h2a_fwng_validate.rc != 0 and h2a_fwng_validate.rc != 127",
                },
                {
                    "name": "Apply fwng policy only when h2a_apply_firewall is true",
                    "ansible.builtin.command": {
                        "argv": ["fwng", "apply", "--config", "/etc/fwng.yaml", "--rollback-after", "60s"]
                    },
                    "when": "h2a_apply_firewall | bool",
                },
            ]
        )
    _write_yaml(ansible / "roles" / "firewall" / "tasks" / "main.yml", tasks)
    return hits, counter


def looks_private(data: bytes) -> bool:
    return b"PRIVATE KEY-----" in data.split(b"\n", 1)[0][:80]


def _base_role(ansible: Path) -> None:
    _write_yaml(
        ansible / "roles" / "base" / "tasks" / "main.yml",
        [{"name": "Set hostname", "ansible.builtin.hostname": {"name": "{{ h2a_hostname }}"}}],
    )


def _plays(ansible: Path, bundle: dict, auto: list[dict], review: list[dict], hits: list[SecretHit]) -> None:
    pre: list[dict] = []
    if hits:
        pre.append(
            {
                "name": "Refuse placeholder secrets",
                "ansible.builtin.assert": {
                    "that": [f"{hit.variable} != 'REPLACE_ME'" for hit in hits],
                    "fail_msg": "Fill group_vars/all/secrets.yml before deploying.",
                },
            }
        )
    roles = [{"role": "base"}] + [{"role": item["name"]} for item in auto] + [{"role": "firewall"}]
    site = {
        "name": f"Rebuild {bundle['hostname']}",
        "hosts": "converted",
        "become": True,
        "roles": roles,
    }
    if pre:
        site["pre_tasks"] = pre
    _write_yaml(ansible / "site.yml", [site])
    review_play = {
        "name": f"Review-only policy for {bundle['hostname']}",
        "hosts": "converted",
        "become": True,
        "roles": [{"role": item["name"]} for item in review] or [{"role": "base"}],
    }
    if not review:
        review_play["roles"] = [{"role": "base"}]
    _write_yaml(ansible / "site-review.yml", [review_play])
    validate_tasks = []
    for service in auto:
        for argv in service.get("validate") or []:
            validate_tasks.append(
                {
                    "name": f"Validate {service['name']}: {argv[0]}",
                    "ansible.builtin.command": {"argv": argv},
                    "changed_when": False,
                }
            )
    if not validate_tasks:
        validate_tasks.append(
            {"name": "No validate commands were collected", "ansible.builtin.debug": {"msg": "nothing to validate"}}
        )
    _write_yaml(
        ansible / "validate.yml",
        [
            {
                "name": f"Validate {bundle['hostname']}",
                "hosts": "converted",
                "become": True,
                "tasks": validate_tasks,
            }
        ],
    )


def _vars(ansible: Path, bundle: dict, hits: list[SecretHit]) -> None:
    group = ansible / "group_vars" / "all"
    group.mkdir(parents=True)
    main = {
        "h2a_hostname": bundle["hostname"],
        "h2a_os_family": bundle["os"]["family"],
        "h2a_apply_firewall": False,
    }
    _write_yaml(group / "main.yml", main)
    lines = [
        "---",
        "# Fill these, then move them into ansible-vault.",
        "# host2ansible does not copy secret values into this tree.",
        "",
    ]
    for hit in hits:
        lines.append(f"# {hit.path}:{hit.line} {hit.kind}")
        lines.append(f"{hit.variable}: REPLACE_ME")
        lines.append("")
    if not hits:
        lines.append("{}")
        lines.append("")
    (group / "secrets.yml").write_text("\n".join(lines), encoding="utf-8")


def _meta(ansible: Path, bundle: dict) -> None:
    (ansible / "ansible.cfg").write_text(
        "[defaults]\ninventory = inventory.example.ini\nroles_path = roles\nhost_key_checking = True\nretry_files_enabled = False\n",
        encoding="utf-8",
    )
    (ansible / "inventory.example.ini").write_text(
        "# Point this at the NEW machine. Do not reuse an address from the investigation.\n"
        "[converted]\n"
        f"new-{bundle['hostname']} ansible_host=192.0.2.10 ansible_user=root\n",
        encoding="utf-8",
    )


def _write_yaml(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("---\n" + yaml.safe_dump(data, sort_keys=False, default_flow_style=False), encoding="utf-8")


def _readme(bundle: dict, hits: list[SecretHit]) -> str:
    services = ", ".join(item["name"] for item in bundle["services"]) or "none"
    gaps = "\n".join(f"- {gap}" for gap in bundle["gaps"]) or "- none"
    return f"""# {bundle['hostname']}

Investigated with host2ansible {bundle['tool_version']} via {bundle['source']['transport']}.
OS family: {bundle['os']['family']} ({bundle['os'].get('pretty') or bundle['os'].get('id')}).

Services: {services}

This directory is the investigation. `ansible/` is what you copy to the machine
that will deploy a **different** host. `run_converted.py` refuses an inventory
whose `ansible_host` is one of the addresses collected here.

```bash
python3 run_converted.py test
# edit ansible/inventory for the new host, fill ansible/group_vars/all/secrets.yml
python3 run_converted.py execute --inventory ansible/inventory --yes
python3 run_converted.py validate --inventory ansible/inventory
```

Firewall apply stays off until `h2a_apply_firewall: true`. Live nftables and
iptables output is under `evidence/firewall/` and is not in the playbook.
sshd and sudoers are in `site-review.yml` only (`--include-review`).

Secrets to fill: {len(hits)}

## Gaps

{gaps}
"""


_SHIM = '''#!/usr/bin/env python3
"""Generated by host2ansible. Runs the Ansible in ./ansible against a new host."""
import pathlib
import sys

try:
    from host2ansible.runner import main
except ImportError:
    sys.stderr.write("host2ansible is not installed on this machine\\n")
    raise SystemExit(2)

if __name__ == "__main__":
    raise SystemExit(main(pathlib.Path(__file__).resolve().parent))
'''
