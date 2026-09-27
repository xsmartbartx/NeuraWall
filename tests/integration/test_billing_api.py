import json

import pytest
from fastapi.testclient import TestClient

from neurawall.core.config import load_settings
from neurawall.security.integrity import EphemeralSigner
from neurawall.services.control_plane.app import create_app
from neurawall.services.control_plane.service import ControlPlane
from tests.unit.test_billing import event, sign

ADMIN = ("admin@neurawall.local", "Admin-Password-1!")
BILLING = {
    "stripe_secret_key": "sk_test_x",
    "stripe_webhook_secret": "whsec_test",
    "price_pro_month": "price_pro_m",
    "price_business_year": "price_biz_y",
}


@pytest.fixture
def env(tmp_path):
    settings = load_settings(
        environment="test",
        data_dir=tmp_path,
        log_json=False,
        auth={"bootstrap_admin_password": ADMIN[1]},
        billing=BILLING,
    )
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    app = create_app(settings, control_plane=cp, start_background=False)
    with TestClient(app) as c:
        r = c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
        yield cp, c, {"Authorization": f"Bearer {r.json()['access_token']}"}


def post_event(c, cp, payload, secret="whsec_test"):
    body = json.dumps(payload).encode()
    return c.post(
        "/api/v1/billing/webhook",
        content=body,
        headers={"Stripe-Signature": sign(body, secret), "content-type": "application/json"},
    )


def test_default_is_community_with_one_node_and_offline_ai(env):
    cp, c, h = env
    st = c.get("/api/v1/billing", headers=h).json()
    assert st["plan"]["id"] == "community" and st["source"] == "licence" and st["self_serve"]
    pro = next(p for p in st["plans"] if p["id"] == "pro")
    assert pro["purchasable"] == {"month": True, "year": False}
    cp.enroll_node(
        cp.create_enrollment_token("a"),
        name="n1",
        hostname="",
        agent_version="1",
        backend="dry-run",
    )
    with pytest.raises(Exception, match="includes 1 enforcement node"):
        cp.enroll_node(
            cp.create_enrollment_token("a"),
            name="n2",
            hostname="",
            agent_version="1",
            backend="dry-run",
        )
    assert cp.advisor.mode == "offline"


def test_webhook_upgrades_then_cancels(env):
    cp, c, h = env
    iid = cp.installation_id
    assert iid.startswith("nwi_")
    assert post_event(c, cp, event(install=iid)).json() == {"status": "applied"}
    st = c.get("/api/v1/billing", headers=h).json()
    assert st["plan"]["id"] == "pro" and st["source"] == "stripe"
    assert st["subscription"]["manageable"]
    for i in range(2, 6):  # Pro includes 5 nodes
        cp.enroll_node(
            cp.create_enrollment_token("a"),
            name=f"n{i}",
            hostname="",
            agent_version="1",
            backend="dry-run",
        )
    post_event(c, cp, event("customer.subscription.deleted", install=iid))
    assert c.get("/api/v1/billing", headers=h).json()["plan"]["id"] == "community"
    audit = c.get("/api/v1/audit?action=billing.", headers=h).json()
    assert audit["total"] == 2


def test_webhook_security(env):
    cp, c, _ = env
    body = json.dumps(event(install=cp.installation_id)).encode()
    bad = c.post("/api/v1/billing/webhook", content=body, headers={"Stripe-Signature": "t=1,v1=x"})
    assert bad.status_code == 401
    assert post_event(c, cp, event(install=cp.installation_id), secret="wrong").status_code == 401
    # Other products' / installations' subscriptions on the shared account: 200 + ignored.
    assert post_event(c, cp, event(install=None)).json() == {"status": "ignored"}
    assert post_event(c, cp, event(install="nwi_other")).json() == {"status": "ignored"}
    assert cp.plan().plan_id == "community"


def test_expired_subscription_falls_back(env):
    cp, c, _ = env
    post_event(c, cp, event(install=cp.installation_id, period_end=1_000_000))
    assert cp.plan().plan_id == "community"


def test_checkout_rbac_and_validation(env, monkeypatch):
    _cp, c, h = env
    monkeypatch.setattr(
        "neurawall.modules.billing.stripe.StripeClient.create_checkout",
        lambda self, **kw: f"https://checkout.stripe.com/{kw['price_id']}",
    )
    r = c.post("/api/v1/billing/checkout", headers=h, json={"plan": "pro", "interval": "month"})
    assert r.status_code == 200 and r.json()["checkout_url"].endswith("price_pro_m")
    assert (
        c.post(
            "/api/v1/billing/checkout", headers=h, json={"plan": "pro", "interval": "year"}
        ).status_code
        == 403
    )  # no price
    assert (
        c.post(
            "/api/v1/billing/checkout",
            headers=h,
            json={"plan": "enterprise_dedicated", "interval": "month"},
        ).status_code
        == 422  # not self-serve: rejected by the request schema
    )
    assert c.post("/api/v1/billing/portal", headers=h).status_code == 404  # nothing to manage
    c.post(
        "/api/v1/users",
        headers=h,
        json={"email": "v@x.io", "role": "approver", "password": "Approver-Pass-1"},
    )
    r = c.post("/api/v1/auth/login", json={"email": "v@x.io", "password": "Approver-Pass-1"})
    vh = {"Authorization": f"Bearer {r.json()['access_token']}"}
    r = c.post(
        "/api/v1/auth/password",
        headers=vh,
        json={"current_password": "Approver-Pass-1", "new_password": "Approver-Pass-2"},
    )
    vh = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert (
        c.post(
            "/api/v1/billing/checkout", headers=vh, json={"plan": "pro", "interval": "month"}
        ).status_code
        == 403
    )
    assert c.get("/api/v1/billing/plans").status_code == 200  # public
