"""Whole-argv policy for read-only collection.

Installed binaries and local profiles remain trusted operator inputs. Unknown
applications may report --version only; other commands need an audited grammar.
"""
from __future__ import annotations

import re


class ReadOnlyViolation(Exception):
    """The command is refused before it is sent to a host."""


_SHOW_SQL = re.compile(r"(?i)show\s+[a-z_][a-z0-9_]*\s*;?\s*\Z")
_VERSION_SQL = re.compile(r"(?i)select\s+version\s*\(\s*\)\s*;?\s*\Z")
# Do not treat wrappers, interpreters or management tools as custom applications.
_DENY = frozenset('sh bash dash zsh ksh ash busybox env timeout nice nohup stdbuf xargs '
    'rm mv cp install tee chmod chown chgrp touch mkdir rmdir ln mknod useradd usermod userdel '
    'groupadd groupmod groupdel passwd chpasswd apt apt-get dnf yum microdnf pacman zypper apk '
    'service reboot shutdown poweroff halt init telinit mkfs fdisk parted wipefs mount umount '
    'iptables-restore ip6tables-restore ufw ebtables arptables curl wget scp rsync nc ncat netcat '
    'socat ssh sudo su doas pkexec perl ruby node php git mysql mariadb sed awk gawk dd'.split())
_EXACT = {
    'uname': {('-s',), ('-a',)},
    'ip': {('-o', version, 'addr', 'show') for version in ('-4', '-6')},
    'ss': {('-H', '-lntu')},
    'dpkg-query': {('-W', '-f', '${Package}\t${Version}\n')},
    'rpm': {('-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\n')},
    'nft': {('list', 'ruleset'), ('--version',), ('-v',)},
    'iptables': {('-S',), ('--list-rules',), ('--version',), ('-V',)},
    'ip6tables': {('-S',), ('--list-rules',), ('--version',), ('-V',)},
    'iptables-save': {()}, 'ip6tables-save': {()},
    'firewall-cmd': {(v,) for v in ('--state', '--version', '--list-all', '--list-all-zones', '--get-default-zone')},
    'docker': {(v,) for v in ('version', 'info', 'ps', 'images')} | {('compose', 'ls'), ('compose', 'version')},
    'podman': {(v,) for v in ('version', 'info', 'ps', 'images')},
    'k3s': {('--version',)}, 'kubectl': {('version', '--client')}, 'crictl': {('--version',)},
    'postconf': {('-n',), ('-d',), ('--version',)},
    'nginx': {('-v',), ('-V',), ('-t',)},
    'apache2ctl': {('-v',), ('-t',)}, 'apachectl': {('-v',), ('-t',)},
    'httpd': {('-v',), ('-t',)},
    'promtool': {('check', 'config', '/etc/prometheus/prometheus.yml')},
}


def _path(value):
    return value.startswith('/') and '\n' not in value and '\r' not in value


def _find(args):
    if len(args) < 3 or args[0] != '-P' or not _path(args[1]):
        return False
    index, depth = 2, 0
    while index < len(args):
        token = args[index]
        if token == '(':
            depth += 1
        elif token == ')':
            depth -= 1
            if depth < 0:
                return False
        elif token in ('-xdev', '-o', '-a', '-print0'):
            pass
        elif token in ('-maxdepth', '-type', '-size', '-name'):
            index += 1
            if index == len(args):
                return False
            value = args[index]
            if token == '-maxdepth' and not re.fullmatch(r'[1-8]', value):
                return False
            if token == '-type' and value not in ('f', 'l'):
                return False
            if token == '-size' and not re.fullmatch(r'[+-]?[0-9]+k', value):
                return False
            if token == '-name' and ('/' in value or '\n' in value):
                return False
        else:
            return False
        index += 1
    return depth == 0 and args[-1] == '-print0'


def assert_read_only(argv: list[str]) -> None:
    if not argv or not all(isinstance(x, str) and x and '\x00' not in x for x in argv):
        raise ReadOnlyViolation('argv must be a list of non-empty strings')
    base, args = argv[0].rsplit('/', 1)[-1], tuple(argv[1:])
    allowed = False
    if base in _DENY or base.startswith(('python', 'mkfs.')):
        pass
    elif base in _EXACT:
        allowed = args in _EXACT[base]
    elif base == 'find':
        allowed = _find(args)
    elif base == 'test':
        allowed = len(args) == 2 and args[0] in ('-e', '-f', '-d', '-L') and _path(args[1])
    elif base == 'head':
        allowed = (len(args) == 4 and args[0] == '-c' and args[1].isdigit()
                   and 0 < int(args[1]) <= 512 * 1024 and args[2] == '--' and _path(args[3]))
    elif base == 'stat':
        allowed = (len(args) == 5 and args[:2] == ('-L', '-c')
                   and args[2] in ('%s %a', '%s %a %U %G') and args[3] == '--' and _path(args[4]))
    elif base == 'readlink':
        allowed = len(args) == 2 and args[0] == '--' and _path(args[1])
    elif base == 'systemctl':
        allowed = (len(args) >= 2 and args[0] in ('cat', 'show', 'status', 'is-active', 'is-enabled',
                   'list-unit-files', 'list-units') and all(
                   x in ('--no-pager', '--plain', '--state=enabled') or
                   re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9@._-]*', x) for x in args[1:]))
    elif base == 'psql':
        # -X prevents startup-file commands; no second query, file or output flag.
        allowed = args in (('--version',), ('-V',)) or (
            len(args) == 3 and args[:2] in (('-X', '-c'), ('-X', '--command'))
            and bool(_SHOW_SQL.fullmatch(args[2].strip()) or _VERSION_SQL.fullmatch(args[2].strip())))
    else:
        allowed = args == ('--version',) and bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', base))
    if not allowed:
        raise ReadOnlyViolation(f'command is not an approved read-only invocation: {base}')
