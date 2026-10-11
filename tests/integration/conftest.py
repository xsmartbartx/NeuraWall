"""Shared fixtures for the integration tests."""

import pytest
from fastapi.testclient import TestClient

from neurawall.core.config import load_settings
from neurawall.security.integrity import EphemeralSigner
from neurawall.services.control_plane.app import create_app
from neurawall.services.control_plane.service import ControlPlane

ADMIN_LOGIN = ("admin@neurawall.local", "Admin-Password-1!")


@pytest.fixture
def env(tmp_path):
    """A control plane with its API and an administrator's bearer header: (cp, client, headers)."""
    settings = load_settings(
        environment="test",
        data_dir=tmp_path,
        log_json=False,
        auth={"bootstrap_admin_password": ADMIN_LOGIN[1]},
    )
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    with TestClient(create_app(settings, control_plane=cp, start_background=False)) as c:
        r = c.post("/api/v1/auth/login", json={"email": ADMIN_LOGIN[0], "password": ADMIN_LOGIN[1]})
        yield cp, c, {"Authorization": f"Bearer {r.json()['access_token']}"}
