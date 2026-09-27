import pytest

from host2ansible.guard import ReadOnlyViolation, assert_read_only


def test_rejects_shell_and_writes():
    for argv in (
        ["bash", "-c", "rm -rf /"],
        ["systemctl", "restart", "nginx"],
        ["nft", "flush", "ruleset"],
        ["iptables-restore"],
        ["iptables", "-A", "INPUT", "-j", "ACCEPT"],
        ["psql", "-c", "DROP TABLE accounts"],
        ["dd", "of=/etc/passwd"],
        ["docker", "exec", "box", "bash"],
        ["k3s", "kubectl", "get", "secrets"],
        ["postconf", "-e", "relayhost=evil"],
        ["firewall-cmd", "--add-port=22/tcp"],
        ["ip", "addr", "add", "192.0.2.1/24", "dev", "eth0"],
    ):
        with pytest.raises(ReadOnlyViolation):
            assert_read_only(argv)


def test_allows_reads():
    for argv in (
        ["systemctl", "cat", "nginx.service"],
        ["nft", "list", "ruleset"],
        ["iptables", "-S"],
        ["iptables-save"],
        ["psql", "--version"],
        ["psql", "-c", "SHOW config_file"],
        ["docker", "ps"],
        ["k3s", "--version"],
        ["postconf", "-n"],
        ["firewall-cmd", "--list-all-zones"],
        ["ip", "-o", "-4", "addr", "show"],
        ["find", "-P", "/etc/nginx", "-type", "f", "-print0"],
        ["nginx", "-v"],
        ["myapp", "--version"],
    ):
        assert_read_only(argv)
