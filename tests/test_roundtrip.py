import json
from pathlib import Path

from host2ansible.investigate import investigate
from host2ansible.profiles import load_many
from host2ansible.render import build
from host2ansible.runner import main
from tests.maptransport import MapTransport

ROOT = Path(__file__).resolve().parents[1]

OS_RELEASE = b"""PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
ID=debian
ID_LIKE=debian
"""

NGINX = b"""user www-data;
worker_processes auto;
events { worker_connections 128; }
http { include /etc/nginx/sites-enabled/*; }
"""

SITE = b"server { listen 80; server_name example.test; root /var/www/html; }\n"
MYAPP = b"listen: 127.0.0.1:8080\npassword: supersecretvalue\n"
KEY = b"-----BEGIN OPENSSH PRIVATE KEY-----\nSUPERSECRETKEYMATERIAL\n-----END OPENSSH PRIVATE KEY-----\n"
SSHD = b"Port 22\nPermitRootLogin no\n"
FWNG = b"version: 1\nhost: web-1\nzones:\n  public:\n    interfaces: [eth0]\n    services:\n      ssh:\n        ports: [22]\n"
UNIT = b"[Service]\nExecStart=/usr/sbin/nginx\n"


def _host() -> MapTransport:
    files = {
        "/etc/os-release": OS_RELEASE,
        "/etc/hostname": b"web-1\n",
        "/etc/nginx/nginx.conf": NGINX,
        "/etc/nginx/sites-available/default": SITE,
        "/etc/myapp/config.yaml": MYAPP,
        "/etc/myapp/server.key": KEY,
        "/etc/ssh/sshd_config": SSHD,
        "/etc/fwng.yaml": FWNG,
        "/lib/systemd/system/nginx.service": UNIT,
    }
    links = {"/etc/nginx/sites-enabled/default": "../sites-available/default"}
    return MapTransport(files, links)


def test_investigate_and_build(tmp_path: Path):
    transport = _host()
    profiles = load_many([ROOT / "profiles" / "myapp.yaml"], [])
    out = investigate(transport, profiles, tmp_path, 5, False)
    raw = b"".join(path.read_bytes() for path in out.rglob("*") if path.is_file())
    assert b"SUPERSECRETKEYMATERIAL" not in raw
    assert b"BEGIN OPENSSH PRIVATE KEY" not in raw
    assert b"supersecretvalue" in (out / "files" / "etc" / "myapp" / "config.yaml").read_bytes()

    bundle = json.loads((out / "investigation.json").read_text(encoding="utf-8"))
    names = {item["name"] for item in bundle["services"]}
    assert {"nginx", "myapp", "sshd"} <= names
    assert bundle["firewall"]["policy"]["path"] == "/etc/fwng.yaml"
    assert bundle["source"]["addresses"] == ["203.0.113.9"]
    assert bundle["firewall"]["replay"] is False
    assert bundle["os"]["family"] == "debian"
    nginx = next(item for item in bundle["services"] if item["name"] == "nginx")
    assert any(link["path"].endswith("sites-enabled/default") for link in nginx["links"])
    assert all(call[0] not in {"bash", "rm", "iptables-restore"} for call in transport.calls)

    hits = build(out, False)
    ansible = b"".join(path.read_bytes() for path in (out / "ansible").rglob("*") if path.is_file())
    assert b"supersecretvalue" not in ansible
    assert b"SUPERSECRETKEYMATERIAL" not in ansible
    assert b"iptables-restore" not in ansible
    assert b"nft -f" not in ansible
    assert b"h2a_secret_myapp_1" in ansible
    assert hits and hits[0].variable == "h2a_secret_myapp_1"
    site = (out / "ansible" / "site.yml").read_text(encoding="utf-8")
    review = (out / "ansible" / "site-review.yml").read_text(encoding="utf-8")
    assert "sshd" not in site
    assert "role: sshd" in review or "\n- role: sshd\n" in review or "sshd" in review
    assert "h2a_apply_firewall" in (out / "ansible" / "roles" / "firewall" / "tasks" / "main.yml").read_text(
        encoding="utf-8"
    )
    link_tasks = (out / "ansible" / "roles" / "nginx" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "link" in link_tasks
    assert main(out, ["test"]) == 0
    inventory = tmp_path / "inventory.ini"
    inventory.write_text("[converted]\nweb-1 ansible_host=203.0.113.9 ansible_user=root\n", encoding="utf-8")
    assert main(out, ["execute", "--inventory", str(inventory), "--yes"]) == 1
