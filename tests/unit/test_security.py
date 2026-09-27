import time

import pytest

from neurawall.core.errors import IntegrityFailure, PolicyViolation
from neurawall.security.audit import build_entry, verify_chain
from neurawall.security.credentials import (
    api_key_matches,
    decode_token,
    generate_api_key,
    hash_password,
    issue_token,
    verify_password,
)
from neurawall.security.integrity import (
    EphemeralSigner,
    FileSigner,
    load_public_key,
    sign_payload,
    verify_envelope,
)
from neurawall.security.ratelimit import HourlyBudget, KeyedRateLimiter
from neurawall.security.rbac import Permission, Role, authorize, enforce_four_eyes


def _trusted(signer):
    return {signer.key_id: load_public_key(signer.public_key_pem())}


def test_sign_and_verify_roundtrip():
    s = EphemeralSigner()
    env = sign_payload({"version": 3, "rules": [{"id": "R-000001"}]}, s)
    assert verify_envelope(env, _trusted(s))["version"] == 3


def test_tampered_bundle_rejected():
    s = EphemeralSigner()
    env = sign_payload({"version": 3}, s)
    forged = env.model_copy(update={"payload": {"version": 4}})
    with pytest.raises(IntegrityFailure):
        verify_envelope(forged, _trusted(s))


def test_untrusted_key_rejected():
    env = sign_payload({"v": 1}, EphemeralSigner())
    with pytest.raises(IntegrityFailure):
        verify_envelope(env, _trusted(EphemeralSigner()))


def test_file_signer_persists_key(tmp_path):
    p = tmp_path / "keys" / "signing.pem"
    a = FileSigner(p)
    b = FileSigner(p)
    assert a.key_id == b.key_id
    assert oct(p.stat().st_mode & 0o777) == "0o600"


def test_audit_chain_detects_tampering():
    entries = []
    prev = None
    for i in range(5):
        prev = build_entry(
            prev=prev,
            ts=time.time(),
            actor="alice",
            action="rule.approve",
            target=f"R-00000{i}",
            detail={"i": i, "token": "secret"},
        )
        entries.append(prev)
    assert verify_chain(entries) == 5
    assert entries[0].detail["token"] == "[REDACTED]"
    altered = entries[2].model_copy(update={"actor": "mallory"})
    with pytest.raises(IntegrityFailure):
        verify_chain([*entries[:2], altered, *entries[3:]])
    with pytest.raises(IntegrityFailure):
        verify_chain([entries[0], *entries[2:]])


def test_rbac_and_four_eyes():
    authorize(Role.ADMIN, Permission.APPROVE_RULES)
    authorize(Role.APPROVER, Permission.APPROVE_RULES)
    with pytest.raises(PolicyViolation):
        authorize(Role.OPERATOR, Permission.APPROVE_RULES)
    with pytest.raises(PolicyViolation):
        authorize(Role.VIEWER, Permission.TRIAGE_ALERTS)
    with pytest.raises(PolicyViolation):
        enforce_four_eyes(author="a", approver="a")
    enforce_four_eyes(author="a", approver="b")


def test_passwords_and_tokens():
    h = hash_password("Correct-Horse-9")
    assert verify_password("Correct-Horse-9", h)
    assert not verify_password("wrong", h)
    with pytest.raises(PolicyViolation):
        hash_password("short")
    t = issue_token(subject="u1", role="admin", secret="s" * 32, ttl_seconds=60)
    assert decode_token(t, secret="s" * 32)["role"] == "admin"
    with pytest.raises(PolicyViolation):
        decode_token(t, secret="x" * 32)
    expired = issue_token(subject="u1", role="admin", secret="s" * 32, ttl_seconds=-10)
    with pytest.raises(PolicyViolation):
        decode_token(expired, secret="s" * 32)


def test_api_keys():
    plain, h = generate_api_key()
    assert plain.startswith("nwk_") and api_key_matches(plain, h)
    assert not api_key_matches(plain + "x", h)


def test_rate_limits():
    rl = KeyedRateLimiter(rate_per_second=0.001, burst=2)
    assert rl.allow("a") and rl.allow("a") and not rl.allow("a")
    assert rl.allow("b")
    b = HourlyBudget(2)
    assert b.try_spend() and b.try_spend() and not b.try_spend()
