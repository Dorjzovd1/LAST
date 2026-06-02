"""Pytest тохиргоо — түр зуурын DB ба mock горимд тестлэнэ."""
from __future__ import annotations

import os
import tempfile

import pytest

# App-ийг import хийхээс ӨМНӨ орчны хувьсагчдыг тааруулна (settings cache хийдэг).
_TMP = tempfile.mkdtemp(prefix="rea_test_")
os.environ["REA_DATABASE_URL"] = f"sqlite:///{os.path.join(_TMP, 'test.db')}"
os.environ["REA_DATA_DIR"] = _TMP
os.environ["REA_RECOVERED_DIR"] = os.path.join(_TMP, "recovered")
os.environ["REA_EXPORT_DIR"] = os.path.join(_TMP, "exports")
os.environ["REA_ALLOW_MOCK"] = "1"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c
