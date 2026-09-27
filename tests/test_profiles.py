from pathlib import Path

import pytest

from host2ansible.profiles import ProfileError, load_builtin, load_profile

ROOT = Path(__file__).resolve().parents[1]


def test_builtins_load():
    profiles = load_builtin()
    names = [profile.name for profile in profiles]
    assert names == sorted(names)
    assert {"nginx", "apache", "postfix", "docker", "k3s", "postgres", "pgbouncer", "pgdog", "pgcat"} <= set(names)


def test_bad_profiles_fail_closed(tmp_path: Path):
    samples = {
        "shell.yaml": "name: bad\ndescription: x\nread_only: true\ndetect:\n  any:\n    - command_ok: [bash, -c, id]\nansible:\n  apply: auto\n",
        "root.yaml": "name: bad\ndescription: x\nread_only: true\ndetect:\n  any:\n    - path: /etc/hostname\ncollect:\n  trees:\n    - path: /\nansible:\n  apply: auto\n",
        "shadow.yaml": "name: bad\ndescription: x\nread_only: true\ndetect:\n  any:\n    - path: /etc/shadow\nansible:\n  apply: auto\n",
        "write.yaml": "name: bad\ndescription: x\nread_only: false\ndetect:\n  any:\n    - path: /etc/hostname\nansible:\n  apply: auto\n",
    }
    for name, body in samples.items():
        path = tmp_path / name
        path.write_text(body, encoding="utf-8")
        with pytest.raises(ProfileError):
            load_profile(path)


def test_example_overrides_nothing_builtin():
    profile = load_profile(ROOT / "profiles" / "myapp.yaml")
    assert profile.name == "myapp"
    assert profile.ansible.apply == "auto"
    assert profile.trees[0].path == "/etc/myapp"
