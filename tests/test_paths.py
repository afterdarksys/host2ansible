import pytest

from host2ansible.paths import PathDenied, assert_file, assert_glob, assert_tree


def test_trees_that_must_not_be_walked():
    for path in ("/", "/etc", "/var/lib/docker", "/var/lib/postgresql", "/var/lib/pgsql", "/home/ryan", "/etc/ssh"):
        with pytest.raises(PathDenied):
            assert_tree(path)


def test_allowed_config_tree():
    assert assert_tree("/etc/nginx") == "/etc/nginx"
    assert assert_tree("/etc/myapp/") == "/etc/myapp"


def test_shadow_and_host_keys():
    for path in ("/etc/shadow", "/etc/ssh/ssh_host_ed25519_key", "/etc/../shadow"):
        with pytest.raises(PathDenied):
            assert_file(path)


def test_sshd_config_is_readable():
    assert assert_file("/etc/ssh/sshd_config") == "/etc/ssh/sshd_config"
    assert assert_file("/etc/ssh/sshd_config.d/50-local.conf")


def test_postgres_glob_is_narrow():
    assert assert_glob("/var/lib/pgsql", ("postgresql.conf", "pg_hba.conf"))
    with pytest.raises(PathDenied):
        assert_glob("/var/lib/pgsql", ("*",))
    with pytest.raises(PathDenied):
        assert_glob("/var/lib/postgresql", ("postgresql.conf",))
