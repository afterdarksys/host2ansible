# host2ansible

Investigate a Linux host without changing it, then render Ansible that can rebuild that host somewhere else.

The investigated machine is never the deploy target. `investigate` only reads. `build` only writes files on the machine where you run it. `run_converted.py` refuses an inventory whose `ansible_host` is an address collected from the source.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'

# Read-only. From your laptop, or with --transport local on the host itself.
.venv/bin/host2ansible investigate --transport ssh --destination root@web-1 \
  --profile-dir ./profiles --out ./investigations

# On the machine that will author the deploy, not on the host you just read.
.venv/bin/host2ansible build --from ./investigations/web-1
python3 investigations/web-1/run_converted.py test
```

Copy `investigations/<hostname>/ansible/` to the controller that will install a new machine. Edit `inventory.example.ini` into a real inventory, fill `group_vars/all/secrets.yml`, then:

```bash
python3 run_converted.py execute --inventory ansible/inventory.ini --yes
python3 run_converted.py validate --inventory ansible/inventory.ini
```

`site.yml` is the rebuild. `site-review.yml` holds sshd, sudoers, and any profile marked `apply: review`. It runs only with `--include-review`.

Firewall apply stays off until `h2a_apply_firewall: true`. When an `/etc/fwng.yaml` was present it is copied and `fwng validate` runs. `fwng apply` uses `--rollback-after 60s` and only then. Live `nft list ruleset` and `iptables-save` output is stored under `evidence/firewall/` and is not rendered into a task. Replaying that snapshot is how a Docker or k3s host gets a stale NAT table back.

## What it collects

OS family (Debian/Ubuntu or RHEL/Rocky and their derivatives), hostname, package list, enabled units, and listening sockets. Then any profile that matches:

| Profile | Looks for |
| --- | --- |
| nginx, apache, postfix | distro config trees |
| postgres | `/etc/postgresql`, plus named `*.conf` under `/var/lib/pgsql` only |
| pgbouncer, pgcat, pgdog | their config files |
| docker, k3s | config, not `/var/lib/docker` or `/var/lib/rancher` or the install script |
| node_exporter, prometheus, grafana | monitoring config |

It does not read `/etc/shadow`, SSH host private keys, or home directories. A file whose first line is a PEM private key is not stored. Other password-shaped values stay in the investigation bundle (mode `0600`) and become `{{ h2a_secret_<service>_<n> }}` in the Ansible tree.

## Custom application profiles

A profile tells investigate what to look for and tells build how to write the role. Drop YAML in a directory and pass `--profile-dir`, or pass `--profile` for one file. A user profile replaces a builtin with the same `name`. `profiles/myapp.yaml` is a complete example.

```yaml
name: myapp
description: Widget service
read_only: true
detect:
  any:
    - path: /etc/myapp/config.yaml
    - systemd: myapp.service
    - command_ok: ["myapp", "--version"]
collect:
  trees:
    - path: /etc/myapp
      exclude_suffixes: [".bak"]
  files:
    - path: /etc/myapp/extra.yaml
      optional: true
  commands:                 # evidence only; stdout is not deployed
    - id: version
      argv: ["myapp", "--version"]
      optional: true
  globs:
    - root: /opt/myapp
      names: [myapp.toml]
      maxdepth: 2
      optional: true
ansible:
  apply: auto               # or review, which stays out of site.yml
  packages:
    debian: [myapp]
    redhat: [myapp]
  service:
    name: myapp             # or names: {debian: ..., redhat: ...}
    state: started
    enabled: true
  validate:
    - argv: ["myapp", "--health"]
```

`argv` is a list, never a shell string. Shells, interpreters, and commands that change the host are rejected when the profile is loaded, before anything is contacted. Unknown keys are rejected. Trees cannot be `/`, `/etc`, `/home`, `/var/lib/docker`, `/var/lib/rancher`, or a Postgres data directory.

Commands are evidence. The files, trees, and named globs are what the role copies.

## Transports

| Transport | Use |
| --- | --- |
| `ssh` | Read a remote host. `BatchMode=yes` and `StrictHostKeyChecking=yes`. `--accept-new-host-key` is an explicit opt-in. There is no password flag. |
| `docker` | Read a running container. This is the first test target. |
| `local` | Read the machine you are on. Still read-only. |

```bash
pytest
```

The container test pulls `debian:bookworm-slim`, plants nginx, a custom app, an fwng policy, and a private key, then checks that the key never lands in the bundle, the password never lands in Ansible, and `ansible-playbook --syntax-check` passes.
