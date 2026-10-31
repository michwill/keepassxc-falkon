"""URL helpers shared by the backend and the filler (Qt-only, no Falkon)."""

from PySide6.QtCore import QUrl


def page_key(url):
    """A URL as we compare and look it up: without its fragment."""
    key = QUrl(url)
    key.setFragment(None)
    return key


def lookup_url(url):
    return page_key(url).toString(QUrl.ComponentFormattingOption.FullyEncoded)


def host_key(url):
    """Falkon's PasswordManager::createHost — what ``PasswordEntry.host`` holds."""
    host = url.host() or url.toString()
    return f"{host}:{url.port()}" if url.port() != -1 else host


def origin(url):
    port = url.port()
    return f"{url.scheme()}://{url.host()}" + (f":{port}" if port != -1 else "")


def is_web(url):
    return url.scheme() in ("http", "https")
