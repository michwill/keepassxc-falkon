"""URL helpers shared by the backend and the filler (Qt-only, no Falkon)."""

from PySide6.QtCore import QUrl


def page_key(url: QUrl) -> QUrl:
    """A URL as we compare and look it up: without its fragment. (Fully
    encoded, a literal "#" can only be the fragment delimiter.)"""
    return QUrl(url.toString(QUrl.ComponentFormattingOption.FullyEncoded).split("#", 1)[0])


def lookup_url(url: QUrl) -> str:
    return page_key(url).toString(QUrl.ComponentFormattingOption.FullyEncoded)


def host_key(url: QUrl) -> str:
    """Falkon's PasswordManager::createHost — what ``PasswordEntry.host`` holds."""
    host = url.host() or url.toString()
    return f"{host}:{url.port()}" if url.port() != -1 else host


def origin(url: QUrl) -> str:
    port = url.port()
    return f"{url.scheme()}://{url.host()}" + (f":{port}" if port != -1 else "")


def is_web(url: QUrl) -> bool:
    return url.scheme() in ("http", "https")
