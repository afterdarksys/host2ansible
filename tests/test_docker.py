import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _docker() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


pytestmark = pytest.mark.skipif(not _docker(), reason="docker daemon is not available")


def test_container_investigate_then_build(tmp_path: Path):
    name = f"h2a-test-{os.getpid()}"
    subprocess.run(["docker", "pull", "debian:bookworm-slim"], check=True, timeout=180)
    subprocess.run(
        ["docker", "run", "-d", "--hostname", "box-1", "--name", name, "debian:bookworm-slim", "sleep", "infinity"],
        check=True,
    )
    try:
        root = tmp_path / "root"
        nginx = root / "nginx"
        (nginx / "sites-available").mkdir(parents=True)
        (nginx / "sites-enabled").mkdir()
        (nginx / "nginx.conf").write_text(
            "events {}\nhttp { include /etc/nginx/conf.d/*.conf; }\n",
            encoding="utf-8",
        )
        (nginx / "sites-available" / "default").write_text("server { listen 80; }\n", encoding="utf-8")
        (nginx / "sites-enabled" / "default").symlink_to("../sites-available/default")
        myapp = root / "myapp"
        myapp.mkdir()
        (myapp / "config.yaml").write_text("password: supersecretvalue\n", encoding="utf-8")
        (myapp / "server.key").write_text(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nSUPERSECRETKEYMATERIAL\n-----END OPENSSH PRIVATE KEY-----\n",
            encoding="utf-8",
        )
        (root / "fwng.yaml").write_text("version: 1\nhost: box-1\n", encoding="utf-8")
        (root / "sshd_config").write_text("Port 22\n", encoding="utf-8")
        subprocess.run(["docker", "exec", name, "mkdir", "-p", "/etc/nginx", "/etc/myapp", "/etc/ssh"], check=True)
        subprocess.run(["docker", "cp", f"{nginx}/.", f"{name}:/etc/nginx"], check=True)
        subprocess.run(["docker", "cp", f"{myapp}/.", f"{name}:/etc/myapp"], check=True)
        subprocess.run(["docker", "cp", str(root / "fwng.yaml"), f"{name}:/etc/fwng.yaml"], check=True)
        subprocess.run(["docker", "cp", str(root / "sshd_config"), f"{name}:/etc/ssh/sshd_config"], check=True)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        out = tmp_path / "investigations"
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "host2ansible",
                "investigate",
                "--transport",
                "docker",
                "--container",
                name,
                "--out",
                str(out),
                "--profile",
                str(ROOT / "profiles" / "myapp.yaml"),
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            # Discovery runs over 100 Docker exec probes; allow slower Docker VMs.
            timeout=300,
        )
        assert proc.returncode == 0, proc.stderr
        bundle_dir = out / "box-1"
        blob = b"".join(path.read_bytes() for path in bundle_dir.rglob("*") if path.is_file())
        assert b"SUPERSECRETKEYMATERIAL" not in blob
        bundle = json.loads((bundle_dir / "investigation.json").read_text(encoding="utf-8"))
        assert bundle["os"]["family"] == "debian"
        assert "myapp" in {item["name"] for item in bundle["services"]}
        assert "nginx" in {item["name"] for item in bundle["services"]}
        built = subprocess.run(
            [sys.executable, "-m", "host2ansible", "build", "--from", str(bundle_dir)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert built.returncode == 0, built.stderr
        ansible = b"".join(path.read_bytes() for path in (bundle_dir / "ansible").rglob("*") if path.is_file())
        assert b"supersecretvalue" not in ansible
        assert b"iptables-restore" not in ansible
        checked = subprocess.run(
            [sys.executable, str(bundle_dir / "run_converted.py"), "test"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert checked.returncode == 0, checked.stderr + checked.stdout
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
