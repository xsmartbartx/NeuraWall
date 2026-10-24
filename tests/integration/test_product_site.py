"""The product site is served at the root; the console moved under /app."""


def test_the_product_site_is_served_at_the_root(env):
    _, c, _ = env
    r = c.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "NeuraWall" in r.text
    assert 'href="/app/"' in r.text  # sign in goes to the console


def test_site_pages_and_assets(env):
    _, c, _ = env
    for path in (
        "/pricing/",
        "/pricing",
        "/security/",
        "/docs/",
        "/docs/detection/",
        "/docs/evasion-report/",
        "/site.css",
        "/site.js",
        "/favicon.svg",
    ):
        assert c.get(path).status_code == 200, path


def test_unknown_pages_get_the_site_404(env):
    _, c, _ = env
    r = c.get("/no-such-page")
    assert r.status_code == 404
    assert "text/html" in r.headers["content-type"]


def test_old_console_links_redirect_under_app(env):
    _, c, _ = env
    r = c.get("/alerts/12?tab=flows", follow_redirects=False)
    assert r.status_code == 308
    assert r.headers["location"] == "/app/alerts/12?tab=flows"
    assert c.get("/app", follow_redirects=False).headers["location"] == "/app/"


def test_the_api_and_probes_are_not_shadowed_by_the_site(env):
    _, c, h = env
    assert c.get("/healthz").json()["status"] == "ok"
    assert c.get("/api/v1/nope", headers=h).status_code == 404
    assert c.get("/api/v1/nope").headers["content-type"].startswith("application/json")


def test_path_traversal_does_not_leave_the_site_directory(env):
    _, c, _ = env
    for path in ("/../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/%00"):
        assert c.get(path).status_code == 404, path


def test_the_sso_handoff_script_forwards_the_fragment_to_the_console(env):
    _, c, _ = env
    js = c.get("/site.js").text
    assert "#sso_token=" in js
    assert '"/app/"' in js


def test_the_docs_landing_links_to_the_live_api_reference(env):
    _, c, _ = env
    page = c.get("/docs/").text
    assert 'href="/api/docs"' in page
    assert 'href="/docs/detection/"' in page
    assert c.get("/api/docs").status_code == 200


def test_the_home_page_links_to_the_demo_instance(env):
    _, c, _ = env
    assert 'href="https://neurawall-demo.onenexora.com/app/"' in c.get("/").text
