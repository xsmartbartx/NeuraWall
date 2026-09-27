"""Runs the control-plane workflows against a real PostgreSQL (CI job `postgres`).

Skipped unless NEURAWALL_TEST_DATABASE_URL points at a disposable database.
"""

import os

import pytest
from sqlalchemy import text

from neurawall.core.config import load_settings
from neurawall.core.models import RuleMode
from neurawall.modules.flow_collector.generator import TrafficGenerator
from neurawall.security.integrity import EphemeralSigner
from neurawall.services.control_plane.service import ControlPlane

PG_URL = os.environ.get("NEURAWALL_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not PG_URL, reason="NEURAWALL_TEST_DATABASE_URL not set")


@pytest.fixture
def cp(tmp_path):
    from neurawall.services.control_plane.db import make_engine

    eng = make_engine(PG_URL)
    with eng.begin() as conn:  # start from an empty schema
        conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public"))
    eng.dispose()
    settings = load_settings(
        environment="test",
        data_dir=tmp_path,
        database_url=PG_URL,
        inference={"baseline_warmup_flows": 50, "isolation_forest_trees": 20},
        auth={"bootstrap_admin_password": "Admin-Password-1!"},
    )
    plane = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    yield plane
    plane.stop()


def test_postgres_full_workflow(cp):
    assert cp.db.engine.dialect.name == "postgresql"
    gen = TrafficGenerator(seed=31)
    cp.ingest("n1", [gen.benign() for _ in range(300)])
    cp.ingest("n1", gen.scenario("c2_beacon", 8) + gen.scenario("sql_injection", 6))
    dash = cp.dashboard(24)
    assert dash["total_flows"] == 314 and dash["timeline"] and dash["labels"]
    alert = next(a for a in cp.list_alerts()[0] if "c2_beacon" in a.labels)
    triaged = cp.triage_alert(alert.id)
    rule = cp.approve_draft("approver", triaged.draft_id, mode=RuleMode.ENFORCE)
    assert rule.id == "R-000008" and cp.latest_version() == 2
    assert cp.rollback_bundle("approver", 2, "test") == 3
    cp.run_maintenance()
    assert cp.verify_audit() >= 5


def test_postgres_schema_matches_models(cp):
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from neurawall.services.control_plane.db import Base

    with cp.db.engine.connect() as conn:
        assert compare_metadata(MigrationContext.configure(conn), Base.metadata) == []
