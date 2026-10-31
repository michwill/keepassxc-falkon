from PySide6.QtCore import QUrl

from keepassxc_falkon.urls import host_key, is_web, lookup_url, origin, page_key


def test_page_key_drops_only_the_fragment():
    url = QUrl("https://Example.com:8443/a%20b/c?x=1&y=%2F#frag")
    assert lookup_url(url) == "https://example.com:8443/a%20b/c?x=1&y=%2F"
    assert page_key(url) == page_key(QUrl("https://example.com:8443/a%20b/c?x=1&y=%2F"))
    assert not page_key(url).hasFragment()


def test_host_key_matches_falkon_create_host():
    assert host_key(QUrl("https://example.com/login")) == "example.com"
    assert host_key(QUrl("http://127.0.0.1:8080/x")) == "127.0.0.1:8080"


def test_origin_and_scheme():
    assert origin(QUrl("https://example.com/a?b#c")) == "https://example.com"
    assert origin(QUrl("http://localhost:3000/")) == "http://localhost:3000"
    assert is_web(QUrl("https://x.org"))
    assert is_web(QUrl("http://x.org"))
    assert not is_web(QUrl("file:///etc/passwd"))
    assert not is_web(QUrl("about:blank"))
