import pytest

from keepassxc_falkon import protocol
from keepassxc_falkon.protocol import KeePassXCClient
from tests.conftest import process_until

URL = "https://example.com/login"


def run(client, job, timeout_ms=5000):
    assert client.wait(job, timeout_ms), "job did not finish"
    return job


def associate(client):
    job = run(client, client.associate())
    assert job.error is None, job.error
    return job


def test_associate_stores_key_and_test_associates_next_session(qapp, fake, store, client):
    associate(client)
    assert store.association(fake.db_hash)["id"] == "falkon-test"
    assert fake.keys["falkon-test"] == store.association(fake.db_hash)["key"]
    assert fake.actions() == ["change-public-keys", "get-databasehash", "associate"]

    # A new session (e.g. Falkon restarted) reuses the stored association.
    fresh = KeePassXCClient(store, paths=lambda: [fake.path])
    fake.clear_received()
    job = run(fresh, fresh.status())
    assert job.result["associated"]
    assert job.result["id"] == "falkon-test"
    assert fake.actions() == ["change-public-keys", "get-databasehash", "test-associate"]
    assert not fake.unencrypted_nested


def test_get_logins_returns_entries_and_caches(client, fake):
    fake.add_entry("https://example.com", "alice", "s3cret")
    fake.add_entry("https://example.com", "bob", "hunter2")
    fake.add_entry("https://other.org", "carol", "x")
    associate(client)

    job = run(client, client.get_logins(URL))
    assert [(e.login, e.password) for e in job.result] == [("alice", "s3cret"), ("bob", "hunter2")]
    assert all(e.uuid for e in job.result)
    sent = dict(fake.received)["get-logins"]
    assert sent["url"] == URL
    assert sent["keys"] == [{"id": "falkon-test", "key": fake.keys["falkon-test"]}]

    fake.clear_received()
    again = client.get_logins(URL)
    assert again.done
    assert again.result == job.result
    assert fake.actions() == []


def test_totp_is_flagged_and_fetched_fresh(client, fake):
    fake.add_entry("https://example.com", "alice", "s3cret", totp="123456")
    fake.add_entry("https://example.com", "bob", "pw")
    associate(client)
    alice, bob = run(client, client.get_logins(URL)).result
    assert alice.has_totp
    assert not bob.has_totp
    assert run(client, client.get_totp(alice.uuid)).result == "123456"


def test_passkeys_carry_options_origin_and_keys(client, fake):
    associate(client)
    fake.passkey_response = {"id": "Y3JlZA", "type": "public-key", "response": {"clientDataJSON": "e30"}}
    options = {"challenge": "Y2hhbGxlbmdlY2hhbGxlbmdl", "rpId": "example.com", "allowCredentials": []}
    job = run(client, client.passkeys("get", options, "https://example.com"))
    assert job.result["id"] == "Y3JlZA"
    action, sent = fake.received[-1]
    assert action == "passkeys-get"
    assert sent["publicKey"] == options
    assert sent["origin"] == "https://example.com"
    assert sent["keys"] == [{"id": "falkon-test", "key": fake.keys["falkon-test"]}]

    fake.passkey_response = {"errorCode": 22}
    job = run(client, client.passkeys("create", {"challenge": "x"}, "https://example.com"))
    assert job.result == {"errorCode": 22}
    action, sent = fake.received[-1]
    assert action == "passkeys-register"
    assert sent["groupName"] == ""
    assert not fake.unencrypted_nested


def test_passkeys_on_a_locked_database_ask_to_unlock(client, fake):
    associate(client)
    fake.set_locked(True)
    process_until(lambda: client.locked is True)
    job = run(client, client.passkeys("get", {"challenge": "x"}, "https://example.com"))
    assert job.error.code == protocol.DATABASE_NOT_OPENED
    assert fake.unlock_requests == 1


def test_lookups_are_cached_per_site_for_a_while(client, fake, monkeypatch):
    fake.add_entry("https://example.com", "alice", "s3cret")
    associate(client)
    run(client, client.get_logins("https://example.com/login"))
    fake.clear_received()
    # Another page of the site, or the same page with a new address: no new
    # request, so no second KeePassXC access dialog for an "Allow" without
    # "Remember".
    for url in ("https://example.com/login?step=2", "https://EXAMPLE.com/account#top"):
        job = client.get_logins(url)
        assert job.done
        assert [e.login for e in job.result] == ["alice"]
    assert fake.actions() == []
    # A different port is a different site.
    run(client, client.get_logins("https://example.com:8443/login"))
    assert fake.actions() == ["get-logins"]
    # And the answer expires.
    monkeypatch.setattr(protocol, "CACHE_TTL_S", 0)
    run(client, client.get_logins("https://example.com/login"))
    assert fake.actions() == ["get-logins", "get-logins"]


def test_concurrent_lookups_for_a_site_share_one_request(client, fake):
    fake.add_entry("https://example.com", "alice", "s3cret")
    associate(client)
    fake.logins_delay = 0.3  # KeePassXC waiting on its access dialog
    first = client.get_logins("https://example.com/login")
    second = client.get_logins("https://example.com/login?next=/")
    assert first is second
    run(client, first)
    assert fake.actions().count("get-logins") == 1


def test_site_key():
    assert protocol.site_key("https://Example.com/a?b#c") == "https://example.com"
    assert protocol.site_key("http://127.0.0.1:8080/x") == "http://127.0.0.1:8080"


def test_no_logins_is_an_empty_result(client, fake):
    associate(client)
    job = run(client, client.get_logins("https://nothing.example/"))
    assert job.error is None
    assert job.result == []


def test_lookup_without_association_does_not_prompt(client, fake):
    job = run(client, client.get_logins(URL))
    assert job.error.code == protocol.NOT_ASSOCIATED
    assert "associate" not in fake.actions()


def test_association_removed_in_keepassxc_is_forgotten(client, fake, store):
    associate(client)
    fake.keys = {}
    fresh = KeePassXCClient(store, paths=lambda: [fake.path])
    job = run(fresh, fresh.get_logins(URL))
    assert job.error.code == protocol.NOT_ASSOCIATED
    assert store.associations() == {}


def test_cancelled_association(client, fake, store):
    fake.associate_as = None
    job = run(client, client.associate())
    assert job.error.code == protocol.ACTION_CANCELLED_OR_DENIED
    assert store.associations() == {}


def test_locked_database_and_unlock(client, fake):
    associate(client)
    fake.locked = True
    job = run(client, client.get_logins(URL))
    assert job.error.code == protocol.DATABASE_NOT_OPENED
    assert client.locked is True

    job = run(client, client.unlock())
    assert job.result is False
    assert fake.unlock_requests == 1

    unlocked = []
    client.databaseUnlocked.connect(lambda: unlocked.append(True))
    fake.add_entry("https://example.com", "alice", "s3cret")
    fake.set_locked(False)
    process_until(lambda: unlocked)
    assert client.locked is False
    job = run(client, client.get_logins(URL))
    assert [e.login for e in job.result] == ["alice"]


def test_associate_while_locked_resumes_after_unlock(client, fake, store):
    fake.locked = True
    job = run(client, client.associate())
    assert job.error.code == protocol.DATABASE_NOT_OPENED
    assert fake.unlock_requests == 1
    fake.set_locked(False)
    process_until(lambda: store.association(fake.db_hash) is not None)


def test_unlock_broadcast_invalidates_cache(client, fake):
    fake.add_entry("https://example.com", "alice", "old")
    associate(client)
    run(client, client.get_logins(URL))
    fake.set_entry_password(0, "new")
    fake.set_locked(False)  # e.g. the user switched database tabs
    process_until(lambda: client.cached_logins(URL) is None)
    job = run(client, client.get_logins(URL))
    assert job.result[0].password == "new"


def test_save_login_adds_updates_and_skips_duplicates(client, fake):
    associate(client)
    job = run(client, client.save_login("https://example.com", "alice", "pw1"))
    assert job.result == "added"
    assert [(e["login"], e["password"]) for e in fake.entries] == [("alice", "pw1")]

    job = run(client, client.save_login("https://example.com", "alice", "pw1"))
    assert job.result == "unchanged"

    job = run(client, client.save_login("https://example.com", "alice", "pw2"))
    assert job.result == "updated"
    assert [(e["login"], e["password"]) for e in fake.entries] == [("alice", "pw2")]
    set_login = [m for a, m in fake.received if a == "set-login"][-1]
    assert set_login["uuid"] == fake.entries[0]["uuid"]

    job = run(client, client.save_login("https://example.com", "bob", "pw3"))
    assert job.result == "added"
    assert len(fake.entries) == 2


def test_writes_are_spaced_so_keepassxc_can_save(client, fake, monkeypatch):
    monkeypatch.setattr(protocol, "WRITE_SPACING_S", 0.6)
    associate(client)
    first = client.save_login("https://example.com", "alice", "pw1")
    second = client.passkeys("create", {"challenge": "x"}, "https://example.com")
    lookup = client.get_logins("https://other.org/")
    run(client, first)
    process_until(lambda: lookup.done and second.done, timeout=5)
    received = list(zip(fake.actions(), fake.received_at, strict=True))
    set_login_at = next(t for a, t in received if a == "set-login")
    register_at = next(t for a, t in received if a == "passkeys-register")
    assert register_at - set_login_at >= 0.5, received
    # Reads aren't held back beyond the write ahead of them in the queue.
    assert lookup.result == []


def test_disconnect_during_write_spacing_fails_cleanly(qapp, sock_path, store, monkeypatch):
    from tests.fake_keepassxc import FakeProcess

    monkeypatch.setattr(protocol, "WRITE_SPACING_S", 0.8)
    fake = FakeProcess(sock_path)
    c = KeePassXCClient(store, paths=lambda: [sock_path])
    associate(c)
    run(c, c.save_login("https://example.com", "alice", "pw1"))
    second = c.save_login("https://example.com", "bob", "pw2")  # waits for the spacing
    process_until(lambda: c._current is second, timeout=2)
    fake.close()  # KeePassXC quits meanwhile
    process_until(lambda: second.done, timeout=5)
    assert second.error is not None
    assert second.error.code in (protocol.DISCONNECTED, protocol.NOT_RUNNING)
    later = c.get_logins("https://example.com/")  # the queue isn't stuck
    process_until(lambda: later.done, timeout=5)
    assert later.error is not None
    assert later.error.code == protocol.NOT_RUNNING


def test_concurrent_lookups_share_and_serialize(client, fake):
    fake.add_entry("https://example.com", "alice", "s3cret")
    fake.add_entry("https://other.org", "carol", "x")
    associate(client)
    fake.clear_received()
    a1 = client.get_logins(URL)
    a2 = client.get_logins(URL)
    b = client.get_logins("https://other.org/")
    assert a1 is a2
    run(client, b)
    assert a1.done
    assert b.done
    assert [e.login for e in a1.result] == ["alice"]
    assert [e.login for e in b.result] == ["carol"]
    assert fake.actions() == ["get-logins", "get-logins"]


def test_sync_wait_times_out_then_completes_async(client, fake):
    fake.add_entry("https://example.com", "alice", "s3cret")
    associate(client)
    fake.logins_delay = 0.5  # KeePassXC showing its access dialog
    got = []
    job = client.get_logins(URL, callback=lambda j: got.append(j.result))
    assert client.wait(job, 50) is False
    process_until(lambda: got, timeout=3)
    assert [e.login for e in got[0]] == ["alice"]
    assert client.cached_logins(URL) == got[0]


def test_coalesced_broadcast_and_reply(client, fake):
    fake.add_entry("https://example.com", "alice", "s3cret")
    associate(client)
    fake.coalesce_next = {"action": "database-locked"}
    job = run(client, client.get_logins(URL))
    assert [e.login for e in job.result] == ["alice"]
    process_until(lambda: client.locked is True)


def test_not_running(qapp, store, tmp_path):
    c = KeePassXCClient(store, paths=lambda: [str(tmp_path / "missing")])
    job = c.get_logins(URL)
    assert job.done
    assert job.error is not None
    assert job.error.code == protocol.NOT_RUNNING
    assert c.running is False


def test_server_restart_reconnects(qapp, sock_path, store):
    from tests.fake_keepassxc import FakeProcess

    fake = FakeProcess(sock_path)
    c = KeePassXCClient(store, paths=lambda: [sock_path])
    fake.add_entry("https://example.com", "alice", "s3cret")
    associate(c)
    keys = dict(fake.keys)
    fake.close()
    process_until(lambda: c.running is False)

    fake = FakeProcess(sock_path)
    fake.keys = keys
    fake.add_entry("https://example.com", "alice", "s3cret")
    try:
        job = run(c, c.get_logins(URL))
        assert [e.login for e in job.result] == ["alice"]
        assert fake.actions()[:3] == ["change-public-keys", "get-databasehash", "test-associate"]
    finally:
        fake.close()


@pytest.mark.parametrize("password", ['quote"brace}{', "ünïcødé ✓", "back\\slash\nnewline"])
def test_awkward_credentials_survive(client, fake, password):
    associate(client)
    run(client, client.save_login("https://example.com", "al}ice", password))
    job = run(client, client.get_logins(URL))
    assert [(e.login, e.password) for e in job.result] == [("al}ice", password)]
    assert not fake.unencrypted_nested
