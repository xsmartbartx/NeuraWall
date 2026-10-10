import csv
import io

import pytest
from fastapi.testclient import TestClient

from neurawall.core.config import load_settings
from neurawall.modules.flow_collector.generator import TrafficGenerator
from neurawall.security.integrity import EphemeralSigner
from neurawall.services.control_plane import db
from neurawall.services.control_plane.api import export
from neurawall.services.control_plane.app import create_app
from neurawall.services.control_plane.service import ControlPlane

ADMIN = ("admin@neurawall.local", "Admin-Password-1!")


@pytest.fixture
def env(tmp_path):
    settings = load_settings(
        environment="test",
        data_dir=tmp_path,
        log_json=False,
        auth={"bootstrap_admin_password": ADMIN[1]},
    )
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    with TestClient(create_app(settings, control_plane=cp, start_background=False)) as c:
        r = c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
        yield cp, c, {"Authorization": f"Bearer {r.json()['access_token']}"}


def parse(resp):
    return list(csv.reader(io.StringIO(resp.text)))


def ingest(cp, n_attack=10):
    gen = TrafficGenerator(seed=3)
    flows = [f for f in (gen.benign() for _ in range(80))] + list(
        gen.scenario("command_injection", n_attack)
    )
    cp.ingest("edge-1", flows)


@pytest.mark.parametrize(
    "value,expected",
    [
        ('=HYPERLINK("http://evil")', '\'=HYPERLINK("http://evil")'),
        ("+1+1", "'+1+1"),
        ("-2", "'-2"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("\tcmd", "'\tcmd"),
        ("\rcmd", "'\rcmd"),
        ("plain", "plain"),
        ("", ""),
        (-5, -5),
        (0.4, 0.4),
        (True, True),
        (None, None),
    ],
)
def test_formula_cells_are_neutralised(value, expected):
    assert export.safe_cell(value) == expected


def test_the_stream_stops_at_the_row_cap():
    calls = []

    def pages(offset, limit):
        calls.append((offset, limit))
        return [[offset + i] for i in range(limit)]

    text = "".join(export.stream_csv(["n"], pages, max_rows=1200))
    assert len(text.splitlines()) == 1 + 1200
    assert calls == [(0, 500), (500, 500), (1000, 200)]


def test_flows_export_matches_the_filter_and_is_metadata_only(env):
    cp, c, h = env
    ingest(cp)
    r = c.get("/api/v1/flows/export.csv?action=blocked", headers=h)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert (
        "attachment" in r.headers["content-disposition"]
        and r.headers["cache-control"] == "no-store"
    )
    rows = parse(r)
    header, body = rows[0], rows[1:]
    assert "payload" not in " ".join(header)
    assert body and all(row[header.index("enforced")] == "True" for row in body)
    listed = c.get("/api/v1/flows?action=blocked&limit=500", headers=h).json()["total"]
    assert len(body) == listed


def test_a_hostile_hostname_cannot_become_a_formula(env):
    cp, c, h = env
    ingest(cp, n_attack=1)
    with cp.db.session() as s:
        row = s.query(db.FlowRow).first()
        row.host = '=cmd|" /C calc"!A0'
        row.labels = "@evil"
    body = parse(c.get("/api/v1/flows/export.csv", headers=h))
    hosts = {r[body[0].index("host")] for r in body[1:]}
    assert '\'=cmd|" /C calc"!A0' in hosts
    assert not any(cell.startswith(("=", "+", "@")) for r in body[1:] for cell in r)


def test_alerts_and_audit_exports(env):
    cp, c, h = env
    ingest(cp)
    alerts = parse(c.get("/api/v1/alerts/export.csv", headers=h))
    assert alerts[0][:3] == ["id", "status", "severity"] and len(alerts) > 1
    audit = parse(c.get("/api/v1/audit/export.csv?action=export.", headers=h))
    assert audit[0][0] == "seq"
    actions = [r[3] for r in parse(c.get("/api/v1/audit/export.csv", headers=h))[1:]]
    assert "export.alerts" in actions  # exporting is itself audited
    assert c.get("/api/v1/audit/verify", headers=h).json()["valid"] is True


def test_exports_follow_the_same_permissions_as_the_lists(env):
    cp, c, h = env
    c.post(
        "/api/v1/users",
        headers=h,
        json={
            "email": "v@example.com",
            "name": "V",
            "role": "viewer",
            "password": "Viewer-Pass-1!x",
        },
    )
    with cp.db.session() as s:
        s.query(db.User).filter_by(email="v@example.com").one().must_change_password = False
    t = c.post("/api/v1/auth/login", json={"email": "v@example.com", "password": "Viewer-Pass-1!x"})
    vh = {"Authorization": f"Bearer {t.json()['access_token']}"}
    assert c.get("/api/v1/flows/export.csv", headers=vh).status_code == 200  # read
    assert c.get("/api/v1/audit/export.csv", headers=vh).status_code == 403  # audit:read only
    assert c.get("/api/v1/flows/export.csv").status_code == 401
