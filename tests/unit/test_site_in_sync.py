"""The committed product site is exactly what scripts/build_site.py generates."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _build_site():
    spec = importlib.util.spec_from_file_location("build_site", ROOT / "scripts/build_site.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_pages_match_the_committed_files():
    site = _build_site()
    expected = {
        "index.html": site.home(),
        "pricing/index.html": site.pricing(),
        "security/index.html": site.security(),
        "docs/index.html": site.docs(),
        "docs/detection/index.html": site.detection(),
        "docs/evasion-report/index.html": site.evasion_report(),
        "404.html": site.not_found(),
    }
    for rel, text in expected.items():
        assert (site.SITE / rel).read_text() == text, f"{rel} is stale: run scripts/build_site.py"


def test_the_evasion_report_page_carries_the_report_headline_and_escapes_payloads():
    site = _build_site()
    page = site.evasion_report()
    source = (ROOT / "docs/evasion-report.md").read_text()
    headline = next(
        line for line in source.splitlines() if line.startswith("**") and "cases" in line
    )
    assert headline.strip("*").split(":")[0] in page.replace("<strong>", "").replace(
        "</strong>", ""
    )
    assert "<script>alert" not in page  # payloads are escaped, never live markup
    assert "&lt;script&gt;" in page


def test_markdown_subset():
    site = _build_site()
    title, body = site.markdown_body(
        "# T\n\n## H\n\nsome **bold** and `a<b` text\n\n- one\n  more\n- two\n"
    )
    assert title == "T"
    assert "<h2>H</h2>" in body
    assert "<strong>bold</strong>" in body and "<code>a&lt;b</code>" in body
    assert "<li>one more</li>" in body and "<li>two</li>" in body
