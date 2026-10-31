import contextlib
import os
import sys
import time

import pytest
from PySide6.QtCore import QCoreApplication

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keepassxc_falkon import protocol
from keepassxc_falkon.protocol import KeePassXCClient
from keepassxc_falkon.store import Store
from tests.fake_keepassxc import FakeProcess


@pytest.fixture(autouse=True)
def no_write_spacing(monkeypatch):
    """Tests that need KeePassXC's save-spacing set it themselves."""
    monkeypatch.setattr(protocol, "WRITE_SPACING_S", 0)


@pytest.fixture(scope="session")
def qapp():
    return QCoreApplication.instance() or QCoreApplication([])


def process_until(predicate, timeout=5.0):
    """Run the Qt event loop until ``predicate()`` holds (or fail)."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("timed out waiting for condition")
        QCoreApplication.processEvents()
        time.sleep(0.005)


@pytest.fixture
def sock_path(tmp_path):
    # Unix socket paths are length-limited; tmp_path can be long.
    import tempfile
    d = tempfile.mkdtemp(prefix="kpxc-")
    yield os.path.join(d, "s")
    with contextlib.suppress(OSError):
        os.rmdir(d)


@pytest.fixture
def fake(sock_path):
    server = FakeProcess(sock_path)
    yield server
    server.close()


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "keepassxc.json"))


@pytest.fixture
def client(qapp, fake, store):
    c = KeePassXCClient(store, paths=lambda: [fake.path])
    yield c
    c.deleteLater()
