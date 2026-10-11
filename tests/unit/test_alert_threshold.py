"""Web-injection labels alert earlier than the rest; nothing here can block."""

import pytest

from neurawall.core.config import PolicySettings
from neurawall.core.models import Action, PolicyBundle, ThreatLabel
from neurawall.modules.policy_engine import PolicyEngine
from neurawall.modules.policy_engine.arbitration import INJECTION_ALERT_THRESHOLD, INJECTION_LABELS
from neurawall.modules.policy_engine.ruleset import Evidence
from tests.conftest import make_flow
from tests.unit.test_policy_engine import classification


def verdict(label, confidence, **bundle):
    f = make_flow()
    ev = Evidence(flow=f, classifications=(classification(f.flow_id, label, confidence),))
    return PolicyEngine(PolicyBundle(version=1, rules=[], **bundle)).evaluate(ev)


@pytest.mark.parametrize("label", sorted(INJECTION_LABELS, key=str))
def test_injection_labels_alert_from_half_and_never_block(label):
    below, at = verdict(label, 0.49), verdict(label, 0.5)
    assert below.action == Action.ALLOW
    assert at.action == Action.ALERT
    assert not at.enforced
    assert at.rule_id is None


@pytest.mark.parametrize("label", [ThreatLabel.DGA, ThreatLabel.DNS_TUNNEL, ThreatLabel.C2_BEACON])
def test_other_labels_keep_the_general_threshold(label):
    assert verdict(label, 0.69).action == Action.ALLOW
    assert verdict(label, 0.7).action == Action.ALERT


def test_a_lower_general_threshold_lowers_the_others_too():
    assert verdict(ThreatLabel.DGA, 0.45, classifier_alert_threshold=0.4).action == Action.ALERT


def test_a_higher_general_threshold_does_not_raise_the_injection_floor_above_it():
    # min(base, 0.5): an operator who raises the general threshold keeps injection at 0.5.
    assert verdict(ThreatLabel.XSS, 0.5, classifier_alert_threshold=0.9).action == Action.ALERT


def test_the_setting_defaults_to_the_unchanged_value_and_is_bounded():
    assert PolicySettings().classifier_alert_threshold == 0.7
    assert INJECTION_ALERT_THRESHOLD == 0.5
    for bad in (0.2, 1.1):
        with pytest.raises(ValueError):
            PolicySettings(classifier_alert_threshold=bad)


def test_published_bundles_carry_the_configured_threshold(tmp_path):
    from neurawall.core.config import load_settings
    from neurawall.security.integrity import EphemeralSigner
    from neurawall.services.control_plane import db
    from neurawall.services.control_plane.service import ControlPlane

    settings = load_settings(
        environment="test",
        data_dir=tmp_path,
        log_json=False,
        policy={"classifier_alert_threshold": 0.6},
    )
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    with cp.db.session() as s:
        payload = (
            s.query(db.BundleRow).order_by(db.BundleRow.version.desc()).first().envelope["payload"]
        )
    assert payload["classifier_alert_threshold"] == 0.6
