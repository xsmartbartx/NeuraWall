"""Claude calls are metered per UTC month; an `included` plan has a budget, after which the
offline advisor answers. Pro uses the customer's own key (no budget), Community has none."""

import time
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from neurawall.core.config import load_settings
from neurawall.core.errors import RecoverableError
from neurawall.core.models import DraftSource, Evidence
from neurawall.modules.flow_collector.generator import TrafficGenerator
from neurawall.modules.l7_classifier import L7Classifier
from neurawall.modules.llm_advisor import schemas
from neurawall.security.integrity import EphemeralSigner
from neurawall.services.control_plane import db
from neurawall.services.control_plane.app import create_app
from neurawall.services.control_plane.service import ControlPlane

ADMIN = ("admin@neurawall.local", "Admin-Password-1!")


class FakeClaude:
    def __init__(self, error=None):
        self.error, self.calls = error, 0

    def last_usage(self):
        return ("claude-test", 1200, 300)

    def generate(self, task, context, output):
        self.calls += 1
        if self.error:
            raise self.error
        return schemas.LlmAlertSummary(
            title="Suspicious egress",
            summary="A host sent data to a rare destination.",
            severity="high",
            recommended_actions=["Review the destination"],
        )


def evidence():
    gen, clf = TrafficGenerator(seed=4), L7Classifier()
    return [
        Evidence(flow=f, classifications=tuple(clf.classify(f))) for f in gen.scenario("dga", 5)
    ]


def make(tmp_path, plan, backend, **billing):
    settings = load_settings(
        environment="test",
        data_dir=tmp_path,
        log_json=False,
        auth={"bootstrap_admin_password": ADMIN[1]},
        billing={"plan": plan, **billing},
    )
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=backend)
    return cp, TestClient(create_app(settings, control_plane=cp, start_background=False))


def rows(cp):
    with cp.db.session() as s:
        return s.query(db.LlmUsage).all()


def test_business_has_a_monthly_budget_then_falls_back_to_offline(tmp_path):
    fake = FakeClaude()
    cp, client = make(tmp_path, "business", fake, llm_calls_business=2)
    with client:
        for _ in range(2):
            assert cp.advisor.summarize_alert(evidence()).source == DraftSource.LLM
        assert cp.advisor.mode == "budget_reached"
        out = cp.advisor.summarize_alert(evidence())
        assert out.source == DraftSource.HEURISTIC  # offline advisor answers
        assert fake.calls == 2  # the third never reached the model
        usage = cp.llm_usage()
        assert (usage["used"], usage["budget"], usage["access"]) == (2, 2, "included")
        assert usage["by_kind"] == {"triage": 2}
        assert [(r.model, r.input_tokens, r.output_tokens) for r in rows(cp)] == [
            ("claude-test", 1200, 300)
        ] * 2


def test_the_budget_resets_with_the_month(tmp_path):
    cp, client = make(tmp_path, "business", FakeClaude(), llm_calls_business=1)
    with client:
        last_month = time.time() - 40 * 86400
        with cp.db.session() as s:
            s.add(db.LlmUsage(ts=last_month, kind="triage", model="m", outcome="ok"))
        assert cp.llm_calls_this_period() == 0
        assert cp.advisor.summarize_alert(evidence()).source == DraftSource.LLM
        assert cp.advisor.summarize_alert(evidence()).source == DraftSource.HEURISTIC


@pytest.mark.parametrize(
    "now,start,end",
    [
        ((2026, 12, 31, 23, 59), (2026, 12, 1), (2027, 1, 1)),
        ((2028, 2, 29, 12, 0), (2028, 2, 1), (2028, 3, 1)),
        ((2026, 1, 1, 0, 0), (2026, 1, 1), (2026, 2, 1)),
    ],
)
def test_the_period_is_the_utc_calendar_month(now, start, end):
    ts = datetime(*now, tzinfo=UTC).timestamp()
    got = ControlPlane._llm_period(ts)
    assert got == (
        datetime(*start, tzinfo=UTC).timestamp(),
        datetime(*end, tzinfo=UTC).timestamp(),
    )


def test_pro_uses_the_customers_own_key_with_no_cap(tmp_path):
    cp, client = make(tmp_path, "pro", FakeClaude())
    with client:
        assert cp.llm_budget() is None
        for _ in range(5):
            assert cp.advisor.summarize_alert(evidence()).source == DraftSource.LLM
        usage = cp.llm_usage()
        assert (usage["used"], usage["budget"], usage["access"]) == (5, None, "own_key")
        assert cp.advisor.mode == "online"


def test_community_never_reaches_the_model(tmp_path):
    fake = FakeClaude()
    cp, client = make(tmp_path, "community", fake)
    with client:
        assert cp.advisor.summarize_alert(evidence()).source == DraftSource.HEURISTIC
        assert fake.calls == 0 and rows(cp) == []
        assert cp.advisor.mode == "offline"
        assert cp.llm_usage()["access"] == "none"


def test_refusals_count_but_errors_do_not(tmp_path):
    cp, client = make(
        tmp_path, "business", FakeClaude(RecoverableError("Claude declined the request"))
    )
    with client:
        cp.advisor.summarize_alert(evidence())
        assert [r.outcome for r in rows(cp)] == ["refused"] and cp.llm_calls_this_period() == 1
    cp2, client2 = make(
        tmp_path / "e", "business", FakeClaude(RecoverableError("Claude API error 500"))
    )
    with client2:
        cp2.advisor.summarize_alert(evidence())
        assert [r.outcome for r in rows(cp2)] == ["error"] and cp2.llm_calls_this_period() == 0


def test_a_metering_failure_never_breaks_triage(tmp_path):
    cp, client = make(tmp_path, "business", FakeClaude())
    with client:
        cp.advisor.on_call = lambda rec: 1 / 0
        assert cp.advisor.summarize_alert(evidence()).source == DraftSource.LLM


def test_old_usage_rows_are_purged_but_this_months_are_kept(tmp_path):
    cp, client = make(tmp_path, "business", FakeClaude())
    with client:
        with cp.db.session() as s:
            s.add(db.LlmUsage(ts=time.time() - 90 * 86400, kind="draft", model="m"))
            s.add(db.LlmUsage(ts=time.time() - 3600, kind="draft", model="m"))
        cp.run_maintenance()
        assert len(rows(cp)) == 1


def test_usage_is_visible_through_the_api_and_billing(tmp_path):
    cp, client = make(tmp_path, "business", FakeClaude(), llm_calls_business=10)
    with client as c:
        h = {
            "Authorization": "Bearer "
            + c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]}).json()[
                "access_token"
            ]
        }
        cp.advisor.summarize_alert(evidence())
        api = c.get("/api/v1/llm/usage", headers=h).json()
        assert (api["used"], api["budget"], api["mode"]) == (1, 10, "online")
        billing = c.get("/api/v1/billing", headers=h).json()
        assert billing["usage"]["llm_calls"] == 1 and billing["usage"]["llm_budget"] == 10
        assert {p["id"]: p["llm_access"] for p in billing["plans"]}["pro"] == "own_key"
        system = c.get("/api/v1/system", headers=h).json()
        assert system["advisor"]["mode"] == "online"
