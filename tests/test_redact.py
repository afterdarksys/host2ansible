from host2ansible.redact import looks_like_private_key, redact_text, to_template


def test_password_becomes_a_vault_variable():
    text = "listen: 127.0.0.1:8080\npassword: supersecretvalue\nuser: www-data\n"
    tokenized, hits = redact_text(text, "myapp", "/etc/myapp/config.yaml")
    rendered = to_template(tokenized, hits)
    assert "supersecretvalue" not in rendered
    assert "{{ h2a_secret_myapp_1 }}" in rendered
    assert "www-data" in rendered
    assert hits[0].line == 2
    assert hits[0].kind == "password"


def test_existing_jinja_is_escaped():
    text = "password: supersecretvalue\nnote: {{ already }}\n"
    tokenized, hits = redact_text(text, "myapp", "/etc/myapp/config.yaml")
    rendered = to_template(tokenized, hits)
    assert "{{ already }}" not in rendered
    assert "{{ '{{' }} already }}" in rendered
    assert "{{ h2a_secret_myapp_1 }}" in rendered


def test_quoted_password_and_uri_and_userlist():
    text = 'admin_password: "two words"\nurl: postgres://app:s3cret@db/app\n'
    tokenized, hits = redact_text(text, "db", "/etc/db/conf")
    rendered = to_template(tokenized, hits)
    assert "two words" not in rendered
    assert "s3cret" not in rendered
    userlist, found = redact_text('"bob" "hunter2"\n', "pgbouncer", "/etc/pgbouncer/userlist.txt")
    assert "hunter2" not in to_template(userlist, found)


def test_certificate_path_is_not_a_secret():
    text = "ssl_certificate_key /etc/ssl/private/site.pem;\n"
    tokenized, hits = redact_text(text, "nginx", "/etc/nginx/nginx.conf")
    assert hits == []
    assert "site.pem" in tokenized


def test_private_key_header():
    assert looks_like_private_key(b"-----BEGIN OPENSSH PRIVATE KEY-----\n")
    assert not looks_like_private_key(b"Port 22\n")
