import time

import pytest

from neurawall.core.errors import NotFound, PolicyViolation, ValidationFailure
from neurawall.modules.anomaly_engine import AnomalyEngine
from neurawall.modules.anomaly_engine.engine import Suppression
from neurawall.modules.flow_collector.generator import TrafficGenerator
from tests.integration.test_api import client, login  # noqa: F401 - fixture
from tests.integration.test_control_plane_service import cp, warm  # noqa: F401 - fixture


def _trained(gen):
    eng = AnomalyEngine(warmup_flows=300, trees=50)
    for _ in range(10):
        eng.score_batch([gen.benign() for _ in range(100)])
    return eng


def test_engine_honours_window_start_and_end():
    gen = TrafficGenerator(seed=41)
    eng = _trained(gen)
    flows = gen.scenario("dga", 20)
    src = f"{flows[0].src_ip}/32"
    now = time.time()
    eng.set_suppressions([Suppression([src], now + 3600, "later", starts=now + 600)])
    assert max(s.score for s in eng.score_batch(flows)) > 0.25  # not started yet
    eng.set_suppressions([Suppression([src], now + 3600, "now", starts=now - 1)])
    assert all(s.score <= 0.25 for s in eng.score_batch(flows))
    eng.set_suppressions([Suppression([src], now - 1, "over", starts=now - 60)])
    assert not eng._is_suppressed(flows[0].src_ip)


def test_service_guards_and_lifecycle(cp):  # noqa: F811
    now = time.time()
    for bad in (["0.0.0.0/0"], ["10.0.0.0/8"], ["2001:db8::/32"], ["not-a-net"], []):
        with pytest.raises(ValidationFailure):
            cp.create_change_window("op", cidrs=bad, starts_at=now, ends_at=now + 600, reason="x")
    with pytest.raises(ValidationFailure, match="24 hours"):
        cp.create_change_window(
            "op", cidrs=["10.1.0.0/16"], starts_at=now, ends_at=now + 25 * 3600, reason="x"
        )
    with pytest.raises(ValidationFailure, match="reason"):
        cp.create_change_window(
            "op", cidrs=["10.1.0.0/16"], starts_at=now, ends_at=now + 600, reason="  "
        )
    w = cp.create_change_window(
        "op", cidrs=["10.20.0.5"], starts_at=now, ends_at=now + 600, reason="deploy v2"
    )
    assert w["status"] == "active" and w["cidrs"] == ["10.20.0.5/32"]
    assert [x["id"] for x in cp.list_change_windows()] == [w["id"]]
    assert len(cp.anomaly._suppressions) == 1
    cp.cancel_change_window("op", w["id"])
    assert cp.list_change_windows() == [] and cp.anomaly._suppressions == []
    assert cp.list_change_windows(include_past=True)[0]["status"] == "cancelled"
    with pytest.raises(PolicyViolation):
        cp.cancel_change_window("op", w["id"])
    with pytest.raises(NotFound):
        cp.cancel_change_window("op", 9999)
    assert cp.verify_audit() > 0


def test_windows_survive_restart_and_dampen_scores(cp, tmp_path):  # noqa: F811
    from neurawall.security.integrity import EphemeralSigner
    from neurawall.services.control_plane.service import ControlPlane

    gen = TrafficGenerator(seed=42)
    warm(cp, gen, 600)
    flows = gen.scenario("dga", 15)
    now = time.time()
    cp.create_change_window(
        "op", cidrs=[flows[0].src_ip], starts_at=now, ends_at=now + 600, reason="patching"
    )
    restarted = ControlPlane(cp.settings, signer=EphemeralSigner(), advisor_backend=None)
    assert len(restarted.anomaly._suppressions) == 1
    scores = restarted.anomaly.score_batch(flows)
    assert all(s.score <= 0.25 for s in scores)
    assert any(a.feature == "change_window_suppression" for a in scores[0].top_features)
    restarted.stop()


def test_api_and_rbac(client):  # noqa: F811
    h = login(client)
    r = client.post(
        "/api/v1/change-windows",
        headers=h,
        json={"cidrs": ["10.30.0.0/24"], "duration_minutes": 30, "reason": "DB migration"},
    )
    assert r.status_code == 201, r.text
    wid = r.json()["id"]
    assert client.get("/api/v1/change-windows", headers=h).json()[0]["id"] == wid
    bad = client.post(
        "/api/v1/change-windows",
        headers=h,
        json={"cidrs": ["0.0.0.0/0"], "duration_minutes": 30, "reason": "x"},
    )
    assert bad.status_code == 422
    too_long = client.post(
        "/api/v1/change-windows",
        headers=h,
        json={"cidrs": ["10.30.0.0/24"], "duration_minutes": 2000, "reason": "x"},
    )
    assert too_long.status_code == 422
    client.post(
        "/api/v1/users",
        headers=h,
        json={"email": "v@corp.io", "role": "viewer", "password": "Viewer-Pass-12"},
    )
    vh = login(client, "v@corp.io", "Viewer-Pass-12")
    r = client.post(
        "/api/v1/auth/password",
        headers=vh,
        json={"current_password": "Viewer-Pass-12", "new_password": "Viewer-Pass-34!"},
    )
    vh = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.get("/api/v1/change-windows", headers=vh).status_code == 200
    assert client.delete(f"/api/v1/change-windows/{wid}", headers=vh).status_code == 403
    assert client.delete(f"/api/v1/change-windows/{wid}", headers=h).status_code == 204
    actions = [a["action"] for a in client.get("/api/v1/audit", headers=h).json()["items"]]
    assert "change_window.create" in actions and "change_window.cancel" in actions
