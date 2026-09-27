import json
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from host2ansible.guard import ReadOnlyViolation, assert_read_only
from host2ansible.investigate import Session, _glob, investigate
from host2ansible.paths import PathDenied, assert_file
from host2ansible.profiles import load_builtin, load_many, load_profile, ProfileError
from host2ansible.render import build, BuildError, _files
from host2ansible.runner import RunnerError, _refuse_source, _checked_inventory, main
from host2ansible.transport import run_local, MAX_COMMAND_BYTES
from tests.maptransport import MapTransport
from tests.test_roundtrip import _host, ROOT


@pytest.mark.parametrize('argv', [
    ['psql', '-X', '-c', 'SHOW config_file', '-c', 'DROP TABLE sentinel'],
    ['psql', '-X', '-c', 'SHOW config_file', '--command=DROP TABLE sentinel'],
    ['psql', '-X', '-c', 'SHOW config_file', '-f', '/tmp/script.sql'],
    ['psql', '-c', 'SHOW config_file'],  # startup file is not disabled
    ['psql', '-X', '-c', 'SHOW config_file', '-o', '/tmp/output'],
    ['find', '-P', '/tmp', '-delete', '-print0'],
    ['find', '-P', '/tmp', '-exec', 'sh', '-c', 'id', ';', '-print0'],
    ['sed', '-i', 's/a/b/', '/tmp/file'],
    ['rpm', '-qa', '--pipe', 'sh'],
    ['ip', '-batch', '/tmp/script', 'addr'],
    ['firewall-cmd', '--state', '--panic-on'],
    ['k3s', 'server', '--version', '--cluster-init'],
    ['myapp', '--version', '--delete-all'],
    ['myapp', '--health'],
])
def test_reject_entire_mutating_argv(argv):
    with pytest.raises(ReadOnlyViolation):
        assert_read_only(argv)


def test_profile_rejects_second_sql_command_before_contact(tmp_path):
    profile = {'name': 'bad', 'description': 'bad', 'read_only': True,
               'detect': {'any': [{'command_ok': ['psql', '-X', '-c', 'SHOW config_file', '-c', 'DROP TABLE sentinel']}]},
               'ansible': {'apply': 'auto'}}
    path = tmp_path / 'bad.yaml'
    path.write_text(yaml.safe_dump(profile))
    with pytest.raises(ProfileError):
        load_profile(path)


SOURCE = {'source': {'addresses': ['203.0.113.9', '2001:db8::1']}}


@pytest.mark.parametrize('text', [
    '[converted]\n203.0.113.9\n',
    '[converted]\nsource ansible_host="203.0.113.9"\n',
    'all:\n  children:\n    converted:\n      hosts:\n        source:\n          ansible_host: 203.0.113.9\n',
    '[converted]\nsource\n[converted:vars]\nansible_host=203.0.113.9\n',
    '[converted:children]\nservers\n[servers]\nsource ansible_host=203.0.113.9\n',
    '[converted]\nsource ansible_host=2001:0db8:0:0:0:0:0:1\n',
    '[converted]\nsource ansible_host=::ffff:203.0.113.9\n',
])
def test_resolved_inventory_refuses_source(tmp_path, text):
    path = tmp_path / ('inventory.yml' if text.startswith('all:') else 'inventory.ini')
    path.write_text(text)
    with pytest.raises(RunnerError, match='refusing to contact'):
        _refuse_source(SOURCE, path, False)


def test_inventory_resolves_dns_and_rejects_any_source_answer(tmp_path):
    path = tmp_path / 'inventory.ini'
    path.write_text('[converted]\nsource ansible_host=alias.example\n')
    with patch('host2ansible.runner.socket.getaddrinfo', return_value=[(2, 1, 6, '', ('203.0.113.9', 0))]):
        with pytest.raises(RunnerError, match='refusing to contact'):
            _refuse_source(SOURCE, path, False)


def test_source_override_is_explicit_and_empty_inventory_still_refused(tmp_path):
    path = tmp_path / 'inventory.ini'
    path.write_text('[converted]\nsource ansible_host=203.0.113.9\n')
    assert _refuse_source(SOURCE, path, True)['_meta']['hostvars']['source']['ansible_host'] == '203.0.113.9'
    path.write_text('[converted]\n')
    with pytest.raises(RunnerError, match='nonempty'):
        _refuse_source(SOURCE, path, True)


@pytest.mark.parametrize('extra', ['ansible_connection=local', 'ansible_ssh_common_args="-o Hostname=203.0.113.9"'])
def test_redirecting_connection_options_are_not_address_proof(tmp_path, extra):
    path = tmp_path / 'inventory.ini'
    path.write_text('[converted]\nnew ansible_host=192.0.2.10 ' + extra + '\n')
    with pytest.raises(RunnerError):
        _refuse_source(SOURCE, path, False)


def test_unknown_source_addresses_fail_closed(tmp_path):
    path = tmp_path / 'inventory.ini'
    path.write_text('[converted]\nnew ansible_host=192.0.2.10\n')
    with pytest.raises(RunnerError, match='source addresses'):
        _refuse_source({'source': {'addresses': []}}, path, False)


@pytest.mark.parametrize('command', ['execute', 'test', 'validate'])
def test_relative_inventory_is_checked_once_and_snapshot_is_executed(tmp_path, monkeypatch, command):
    bundle = tmp_path / 'bundle'
    ansible = bundle / 'ansible'
    ansible.mkdir(parents=True)
    (bundle / 'investigation.json').write_text(json.dumps(SOURCE))
    (ansible / 'site.yml').write_text('[]')
    inventory = ansible / 'inventory.ini'
    inventory.write_text('[converted:children]\nweb\n[web]\nnew ansible_host=192.0.2.10\n')
    # This is the unchecked alternate path the original runner accidentally used.
    (ansible / 'ansible').mkdir()
    (ansible / 'ansible' / 'inventory.ini').write_text('[converted]\n203.0.113.9\n')
    monkeypatch.chdir(bundle)
    calls = []
    def playbook(cwd, argv):
        if '--syntax-check' in argv:
            return 0
        checked = Path(argv[argv.index('-i') + 1])
        assert checked.is_absolute() and checked != inventory
        # Mutating the original after validation cannot change the executed target.
        inventory.write_text('[converted]\n203.0.113.9\n')
        resolved = subprocess.run(['ansible-inventory', '-i', str(checked), '--list'],
                                  capture_output=True, check=True, cwd=cwd)
        value = json.loads(resolved.stdout)
        assert value['_meta']['hostvars']['new']['ansible_host'] == '192.0.2.10'
        assert value['converted']['children'] == ['web']
        calls.append(checked)
        return 0
    monkeypatch.setattr('host2ansible.runner._ansible', playbook)
    argv = [command, '--inventory', 'ansible/inventory.ini']
    if command == 'execute':
        argv.append('--yes')
    assert main(bundle, argv) == 0
    assert len(calls) == 1 and not calls[0].exists()


def test_postgres_configs_survive_glob_and_build(tmp_path):
    transport = _host()
    transport.files['/var/lib/pgsql/data/postgresql.conf'] = b'port = 5432\n'
    profiles = load_many([], [])
    bundle = investigate(transport, profiles, tmp_path, 5, False)
    manifest = json.loads((bundle / 'investigation.json').read_text())
    postgres = next(s for s in manifest['services'] if s['name'] == 'postgres')
    assert [r['path'] for r in postgres['files']] == ['/var/lib/pgsql/data/postgresql.conf']
    build(bundle, False)
    assert (bundle / 'ansible/roles/postgres/files/var/lib/pgsql/data/postgresql.conf').read_text() == 'port = 5432\n'
    for path in ('/var/lib/pgsql/data/base/123', '/var/lib/pgsql/data/PG_VERSION'):
        with pytest.raises(PathDenied):
            assert_file(path)


def test_unreadable_discovered_postgres_file_is_incomplete():
    profile = next(p for p in load_builtin() if p.name == 'postgres')
    transport = MapTransport({'/var/lib/pgsql/data/postgresql.conf': b'port = 5432\n'})
    session = Session(transport, 5)
    with patch.object(session, 'read_file', return_value=None):
        records, incomplete = _glob(session, 'postgres', profile.globs[0])
    assert not records and incomplete


@pytest.mark.parametrize('content,module', [('listen: 8080\n','copy'), ('password: test-secret\n','template')])
def test_named_ownership_is_collected_and_rendered(tmp_path, content, module):
    transport = _host()
    transport.files['/etc/myapp/config.yaml'] = content.encode()
    original = transport.do_stat
    def service_owner(argv):
        result = original(argv)
        if argv[-1] == '/etc/myapp/config.yaml':
            result.stdout = f'{len(content)} 600 appsvc appgroup\n'.encode()
        return result
    transport.do_stat = service_owner
    bundle = investigate(transport, load_many([ROOT / 'profiles/myapp.yaml'], []), tmp_path, 5, False)
    build(bundle, False)
    tasks = yaml.safe_load((bundle / 'ansible/roles/myapp/tasks/main.yml').read_text())
    body = next(t['ansible.builtin.' + module] for t in tasks if 'ansible.builtin.' + module in t)
    assert body['mode'] == '0600'
    assert body['owner'] == "{{ h2a_owner_map['appsvc'] }}"
    assert body['group'] == "{{ h2a_group_map['appgroup'] }}"
    variables = yaml.safe_load((bundle / 'ansible/group_vars/all/main.yml').read_text())
    assert variables['h2a_owner_map']['appsvc'] == 'appsvc'
    assert variables['h2a_group_map']['appgroup'] == 'appgroup'


def test_legacy_missing_ownership_requires_reinvestigation(tmp_path):
    (tmp_path / 'config').write_text('listen: 8080')
    service = {'name': 'app', 'files': [{'path': '/etc/app/config', 'relpath': 'config', 'mode': '0600'}]}
    with pytest.raises(BuildError, match='investigate again'):
        _files(tmp_path / 'role', tmp_path, service, 1, False)


@pytest.mark.parametrize('stream', ['stdout', 'stderr'])
def test_output_limit_stops_writer_before_later_side_effect(tmp_path, stream):
    marker = tmp_path / 'should-not-exist'
    script = f'import sys,time,pathlib; sys.{stream}.buffer.write(b"x" * {MAX_COMMAND_BYTES * 2}); sys.{stream}.flush(); time.sleep(2); pathlib.Path({str(marker)!r}).touch()'
    started = time.monotonic()
    result = run_local([sys.executable, '-c', script], 5, ['synthetic-output'])
    assert result.truncated and result.rc == 125 and not result.timed_out
    assert len(getattr(result, stream)) == MAX_COMMAND_BYTES
    assert time.monotonic() - started < 2
    assert not marker.exists()


def test_timeout_is_bounded_even_when_descendant_retains_pipes():
    script = 'import subprocess,sys; subprocess.Popen([sys.executable,"-c","import time; time.sleep(10)"])'
    started = time.monotonic()
    result = run_local([sys.executable, '-c', script], .2, ['synthetic-timeout'])
    assert result.timed_out and result.rc == 124
    assert time.monotonic() - started < 2
