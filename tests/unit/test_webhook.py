import json

import httpx
import pytest

from neurawall.core.errors import ValidationFailure
from neurawall.modules.notify import WebhookError, check_url, derive_secret, send_webhook, sign

PUBLIC = "93.184.216.34"


def resolves(*addrs):
    return lambda host, port: list(addrs)


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example.com/x",
        "ftp://hooks.example.com/x",
        "hooks.example.com/x",
        "https://user:pw@hooks.example.com/x",
        "https://hooks.example.com:notaport/x",
        "https://",
        "https://1.2.3.4/x",
        "https://[2606:4700::1]/x",
        "https://hooks.example.com/x y",
        "https://hooks.example.com/\x00",
        "https://hooks.example.com/" + "a" * 600,
    ],
)
def test_malformed_or_unsafe_urls_are_refused(url):
    with pytest.raises(ValidationFailure):
        check_url(url, resolver=resolves(PUBLIC))


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.9.9",
        "192.168.1.1",
        "169.254.169.254",  # cloud metadata
        "100.64.0.1",  # carrier-grade NAT
        "0.0.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:10.0.0.1",  # IPv4-mapped private
        "::ffff:127.0.0.1",
    ],
)
def test_names_that_resolve_to_internal_addresses_are_refused(address):
    with pytest.raises(ValidationFailure, match="public"):
        check_url("https://hooks.example.com/x", resolver=resolves(address))


def test_one_internal_answer_among_public_ones_is_enough_to_refuse():
    """DNS rebinding sets up a name with both a public and an internal record."""
    with pytest.raises(ValidationFailure):
        check_url("https://hooks.example.com/x", resolver=resolves(PUBLIC, "10.1.1.1"))


def test_unresolvable_hosts_are_refused():
    with pytest.raises(ValidationFailure, match="resolve"):
        check_url("https://nope.example.com/x", resolver=resolves())


def test_a_public_https_url_passes_and_keeps_path_query_and_port():
    host, path, port, addrs = check_url(
        "https://hooks.example.com:8443/services/T0/B0?token=abc", resolver=resolves(PUBLIC)
    )
    assert (host, path, port, addrs) == (
        "hooks.example.com",
        "/services/T0/B0?token=abc",
        8443,
        [PUBLIC],
    )
    assert check_url("https://hooks.example.com", resolver=resolves(PUBLIC))[1:3] == ("/", 443)


def test_signature_is_a_stable_hmac_over_timestamp_and_body():
    assert sign("whsec_k", 1700000000, b'{"a":1}') == sign("whsec_k", 1700000000, b'{"a":1}')
    assert sign("whsec_k", 1700000000, b'{"a":1}') != sign("whsec_k", 1700000001, b'{"a":1}')
    assert sign("whsec_k", 1700000000, b'{"a":1}') != sign("whsec_x", 1700000000, b'{"a":1}')
    assert sign("whsec_k", 1, b"x").startswith("sha256=") and len(sign("whsec_k", 1, b"x")) == 71


def test_secrets_are_derived_per_channel_and_per_server_key():
    a = derive_secret("server-key", "nonce-1")
    assert a == derive_secret("server-key", "nonce-1") and a.startswith("whsec_")
    assert a != derive_secret("server-key", "nonce-2")
    assert a != derive_secret("other-key", "nonce-1")


class Receiver:
    def __init__(self, status=200, raises=None):
        self.status, self.raises, self.requests = status, raises, []

    def __call__(self, request):
        self.requests.append(request)
        if self.raises:
            raise self.raises
        return httpx.Response(self.status, headers={"location": "http://169.254.169.254/"})


def send(rx, url="https://hooks.example.com/h", resolver=None, payload=None, now=1700000000.5):
    return send_webhook(
        url,
        "whsec_test",
        payload or {"event": "alert.created", "text": "hi"},
        now=now,
        resolver=resolver or resolves(PUBLIC),
        transport=httpx.MockTransport(rx),
    )


def test_the_request_is_pinned_signed_and_addressed_by_name():
    rx = Receiver()
    assert send(rx) == 200
    (req,) = rx.requests
    assert req.method == "POST"
    assert req.url.host == PUBLIC  # connects to the address that was checked
    assert req.headers["host"] == "hooks.example.com"  # ...but speaks for the real name
    assert req.extensions["sni_hostname"] == "hooks.example.com"  # and verifies its certificate
    ts = req.headers["x-neurawall-timestamp"]
    assert ts == "1700000000"
    assert req.headers["x-neurawall-signature"] == sign("whsec_test", int(ts), req.content)
    assert json.loads(req.content)["event"] == "alert.created"


def test_ipv6_targets_are_bracketed():
    rx = Receiver()
    send(rx, resolver=resolves("2606:4700:4700::1111"))
    assert rx.requests[0].url.host == "2606:4700:4700::1111"


def test_a_redirect_is_not_followed_and_counts_as_failure():
    rx = Receiver(status=302)
    with pytest.raises(WebhookError, match="302"):
        send(rx)
    assert len(rx.requests) == 1  # nothing went to the Location


@pytest.mark.parametrize("status", [400, 404, 500, 503])
def test_non_2xx_is_a_failure(status):
    with pytest.raises(WebhookError, match=str(status)):
        send(Receiver(status=status))


def test_network_errors_are_failures_not_crashes():
    with pytest.raises(WebhookError, match="unreachable"):
        send(Receiver(raises=httpx.ConnectTimeout("slow")))


def test_an_address_that_turned_internal_is_never_contacted():
    rx = Receiver()
    with pytest.raises(ValidationFailure):
        send(rx, resolver=resolves("10.0.0.9"))
    assert rx.requests == []


def test_an_oversized_payload_is_refused():
    with pytest.raises(ValidationFailure, match="too large"):
        send(Receiver(), payload={"x": "a" * 70_000})


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost/x",
        "https://localhost./x",
        "https://2130706433/x",  # 127.0.0.1 as one integer
        "https://0x7f000001/x",  # ...in hex
        "https://017700000001/x",  # ...in octal
        "https://127.1/x",  # short form
        "https://0/x",  # 0.0.0.0
    ],
)
def test_numeric_and_local_spellings_are_refused_with_the_real_resolver(url):
    """No stubbed DNS here: whatever the system resolver makes of the name must be refused."""
    with pytest.raises(ValidationFailure):
        check_url(url)
