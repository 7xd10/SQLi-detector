"""Target parsing, scope, deny list, HTML parsing and the bounded crawl."""

from __future__ import annotations

import pytest

from helpers import ScriptedTransport, response
from sqliscan.crawl import (
    DEFAULT_DENY,
    CrawlOutcome,
    CrawlSettings,
    DenyList,
    Form,
    Scope,
    TargetError,
    canonicalise,
    crawl,
    load_robots,
    parse_page,
    parse_target,
    resolve_links,
    robots_allows,
)
from sqliscan.http import BudgetExceeded, Request, RequestBudget, TransportError
from sqliscan.models import Method

# -- target parsing ---------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "https://example.com/"),
        ("  example.com  ", "https://example.com/"),
        ("https://example.com", "https://example.com/"),
        ("http://example.com/a/b?x=1", "http://example.com/a/b?x=1"),
        ("HTTPS://Example.COM/Path", "https://example.com/Path"),
        ("https://example.com:8443/", "https://example.com:8443/"),
        ("http://example.com:80/", "http://example.com/"),
    ],
)
def test_parse_target_normalises(raw: str, expected: str) -> None:
    assert parse_target(raw) == expected


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "empty target"),
        ("   ", "empty target"),
        ("ftp://example.com/", "unsupported scheme"),
        ("file:///etc/passwd", "unsupported scheme"),
        ("https://user:pass@example.com/", "credentials"),
        ("https:///nohost", "no host"),
        ("https://example.com:notaport/", "invalid port"),
    ],
)
def test_parse_target_rejects(raw: str, message: str) -> None:
    with pytest.raises(TargetError, match=message):
        parse_target(raw)


def test_parse_target_error_is_a_value_error() -> None:
    assert issubclass(TargetError, ValueError)


def test_canonicalise_drops_fragment_and_default_port() -> None:
    assert canonicalise("https://a.example:443/x#frag") == "https://a.example/x"


def test_canonicalise_keeps_a_non_default_port() -> None:
    assert canonicalise("http://a.example:8080/x") == "http://a.example:8080/x"


def test_canonicalise_lowercases_scheme_and_host() -> None:
    assert canonicalise("HTTP://A.Example/X") == "http://a.example/X"


def test_canonicalise_brackets_ipv6() -> None:
    assert canonicalise("http://[::1]:8080/x") == "http://[::1]:8080/x"


def test_canonicalise_adds_a_root_path() -> None:
    assert canonicalise("https://a.example") == "https://a.example/"


@pytest.mark.parametrize(
    "url",
    ["mailto:a@b.example", "javascript:alert(1)", "https:///nohost", "https://a:bad/x"],
)
def test_canonicalise_rejects(url: str) -> None:
    assert canonicalise(url) is None


# -- scope ------------------------------------------------------------------


def test_scope_allows_the_seed_host() -> None:
    scope = Scope.from_url("https://example.com/a")
    assert scope.allows("https://example.com/other")
    assert scope.allows("http://example.com/")  # scheme is not restricted
    assert scope.allows("https://example.com:8443/")  # nor is the port


def test_scope_is_case_insensitive_on_the_host() -> None:
    scope = Scope(["example.com"])
    assert scope.allows("https://EXAMPLE.COM/")


def test_scope_rejects_other_hosts_by_default() -> None:
    scope = Scope(["example.com"])
    assert not scope.allows("https://other.example/")
    assert not scope.allows("https://example.com.evil.test/")


def test_scope_rejects_a_url_without_a_host() -> None:
    assert not Scope(["example.com"]).allows("mailto:a@example.com")


def test_scope_subdomains_when_asked() -> None:
    scope = Scope(["example.com"], include_subdomains=True)
    assert scope.allows("https://api.example.com/v1")
    assert scope.allows("https://example.com/")
    assert not scope.allows("https://notexample.com/")
    assert not scope.allows("https://example.com.evil.test/")


def test_scope_extend_adds_hosts_without_mutating() -> None:
    original = Scope(["example.com"])
    extended = original.extend(["API.Example.com"])
    assert extended.hosts == ("api.example.com", "example.com")
    assert original.hosts == ("example.com",)


def test_scope_extend_preserves_the_subdomain_flag() -> None:
    extended = Scope(["example.com"], include_subdomains=True).extend(["b.example"])
    assert extended.allows("https://deep.b.example/")


# -- deny list --------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/logout",
        "https://example.com/LOG_OUT",
        "https://example.com/account/delete",
        "https://example.com/cart/checkout?step=2",
        "https://example.com/unsubscribe",
    ],
)
def test_deny_list_blocks_state_changing_paths(url: str) -> None:
    assert DenyList().blocks(url)


@pytest.mark.parametrize(
    "url",
    ["https://example.com/", "https://example.com/products?id=1", "/search?q=x"],
)
def test_deny_list_allows_read_only_paths(url: str) -> None:
    assert not DenyList().blocks(url)


def test_deny_list_accepts_extra_patterns() -> None:
    deny = DenyList(extra=[r"/admin", r"/internal"])
    assert deny.blocks("https://example.com/admin/users")
    assert not deny.blocks("https://example.com/products")
    assert len(deny) == len(DEFAULT_DENY) + 2


# -- html parsing -----------------------------------------------------------


def test_parse_page_collects_links_and_base() -> None:
    html = """
    <html><head><base href="/app/"></head>
    <body>
      <a href="page.php?id=1">one</a>
      <area href="/area">
      <iframe src="/frame"></iframe>
      <a href="#top">skip</a>
      <a href="javascript:void(0)">skip</a>
      <a href="mailto:a@b.example">skip</a>
      <a href="tel:+100">skip</a>
      <a href="data:text/html,x">skip</a>
    </body></html>
    """
    base, links, forms = parse_page(html)
    assert base == "/app/"
    assert links == ("page.php?id=1", "/area", "/frame")
    assert forms == ()


def test_parse_page_collects_a_post_form() -> None:
    html = """
    <form action="/login" method="post">
      <input name="user" value="bob">
      <input type="password" name="pass">
      <input type="submit" value="go">
      <input type="checkbox" name="remember">
      <input type="checkbox" name="keep" checked>
      <input type="file" name="avatar">
      <textarea name="notes">hi</textarea>
      <select name="colour"></select>
      <button type="submit" name="act" value="login">Login</button>
      <button type="button" name="ignored" value="x">x</button>
    </form>
    """
    _base, _links, forms = parse_page(html)
    assert len(forms) == 1
    form = forms[0]
    assert form.action == "/login"
    assert form.method is Method.POST
    assert form.has_file is True
    assert form.fields == (
        ("user", "bob"),
        ("pass", ""),
        ("keep", ""),
        ("notes", ""),
        ("colour", ""),
        ("act", "login"),
    )


def test_parse_page_defaults_to_get() -> None:
    _base, _links, forms = parse_page('<form action="/search"><input name="q"></form>')
    assert forms[0].method is Method.GET
    assert forms[0].fields == (("q", ""),)


def test_parse_page_survives_malformed_markup() -> None:
    _base, links, _forms = parse_page('<a href="/a">unclosed <b>bold</a')
    assert links == ("/a",)


def test_parse_page_of_plain_text_has_nothing() -> None:
    assert parse_page("just words") == (None, (), ())


# -- link resolution --------------------------------------------------------


def test_resolve_links_absolutises_and_dedupes() -> None:
    links = resolve_links(
        ["a", "/a", "https://example.com/a", "./b", "../c"],
        "https://example.com/dir/page",
        None,
        scope=Scope(["example.com"]),
        deny=DenyList(),
    )
    assert links == [
        "https://example.com/dir/a",
        "https://example.com/a",
        "https://example.com/dir/b",
        "https://example.com/c",
    ]


def test_resolve_links_honours_base_href() -> None:
    links = resolve_links(
        ["page"],
        "https://example.com/ignored/seed",
        "/app/",
        scope=Scope(["example.com"]),
        deny=DenyList(),
    )
    assert links == ["https://example.com/app/page"]


def test_resolve_links_drops_out_of_scope_and_denied() -> None:
    links = resolve_links(
        ["https://evil.test/x", "/logout", "/ok"],
        "https://example.com/",
        None,
        scope=Scope(["example.com"]),
        deny=DenyList(),
    )
    assert links == ["https://example.com/ok"]


@pytest.mark.parametrize(
    "href",
    [
        "/logo.png",
        "/app.js",
        "/style.CSS",
        "/doc.pdf",
        "/archive.tar.gz",
        "/font.woff2",
    ],
)
def test_resolve_links_skips_static_assets(href: str) -> None:
    resolved = resolve_links(
        [href],
        "https://example.com/",
        None,
        scope=Scope(["example.com"]),
        deny=DenyList(),
    )
    assert resolved == []


def test_resolve_links_keeps_a_dotted_path_without_an_extension() -> None:
    links = resolve_links(
        ["/v1.2/report"],
        "https://example.com/",
        None,
        scope=Scope(["example.com"]),
        deny=DenyList(),
    )
    assert links == ["https://example.com/v1.2/report"]


# -- robots ----------------------------------------------------------------


def test_load_robots_of_none_is_none() -> None:
    assert load_robots(None) is None


def test_robots_blocks_a_disallowed_path() -> None:
    robots = load_robots("User-agent: *\nDisallow: /private\n")
    assert robots is not None
    assert robots_allows(robots, "sqliscan", "https://example.com/private/x") is False
    assert robots_allows(robots, "sqliscan", "https://example.com/public") is True


def test_robots_absent_allows_everything() -> None:
    assert robots_allows(None, "sqliscan", "https://example.com/anything") is True


# -- the crawl --------------------------------------------------------------


def settings(**overrides: object) -> CrawlSettings:
    defaults: dict[str, object] = {
        "depth": 1,
        "max_urls": 20,
        "workers": 2,
        "timeout": 2.0,
        "respect_robots": False,
    }
    defaults.update(overrides)
    return CrawlSettings(**defaults)  # type: ignore[arg-type]


def crawl_site(transport: ScriptedTransport, **overrides: object) -> CrawlOutcome:
    return crawl(
        "https://example.com/",
        transport=transport,
        scope=Scope(["example.com"]),
        deny=DenyList(),
        settings=settings(**overrides),
    )


def route(
    transport: ScriptedTransport, suffix: str, body: str, **kwargs: object
) -> None:
    transport.add(
        lambda request: request.url.endswith(suffix),
        lambda request: response(request.url, body, **kwargs),  # type: ignore[arg-type]
    )


def test_crawl_fetches_the_seed() -> None:
    transport = ScriptedTransport()
    route(transport, "/", "<a href='/a'>a</a>")

    outcome = crawl_site(transport, depth=0)

    assert outcome.seed == "https://example.com/"
    assert [page.url for page in outcome.pages] == ["https://example.com/"]
    assert outcome.stats.pages_fetched == 1
    assert outcome.stats.urls_discovered == 1
    assert outcome.stats.truncated is False


def test_crawl_follows_links_one_level() -> None:
    transport = ScriptedTransport()
    route(transport, "/", "<a href='/a'>a</a>")
    route(transport, "/a", "<a href='/deep'>d</a>")

    outcome = crawl_site(transport, depth=1)

    assert sorted(page.url for page in outcome.pages) == [
        "https://example.com/",
        "https://example.com/a",
    ]
    assert outcome.stats.urls_discovered == 2


def test_crawl_depth_zero_fetches_only_the_seed() -> None:
    transport = ScriptedTransport()
    route(transport, "/", "<a href='/a'>a</a><a href='/b'>b</a>")

    outcome = crawl_site(transport, depth=0)

    assert outcome.stats.pages_fetched == 1
    assert outcome.stats.urls_discovered == 2
    assert outcome.seed == "https://example.com/"


def test_crawl_honours_max_urls_and_reports_truncation() -> None:
    transport = ScriptedTransport()
    route(transport, "/", "<a href='/1'>1</a><a href='/2'>2</a><a href='/3'>3</a>")

    outcome = crawl_site(transport, depth=1, max_urls=2)

    assert outcome.stats.pages_fetched == 2
    assert outcome.stats.truncated is True


def test_crawl_of_a_single_page_is_not_truncated() -> None:
    transport = ScriptedTransport()
    assert crawl_site(transport, max_urls=1).stats.truncated is False


def test_crawl_counts_transport_failures_without_aborting() -> None:
    transport = ScriptedTransport()

    def boom(request: Request) -> object:
        raise TransportError("connection reset")

    transport.add(lambda request: request.url.endswith("/bad"), boom)  # type: ignore[arg-type]
    route(transport, "/", "<a href='/bad'>bad</a><a href='/good'>good</a>")
    route(transport, "/good", "ok")

    outcome = crawl_site(transport, depth=1)

    assert outcome.stats.pages_failed == 1
    assert "https://example.com/good" in [page.url for page in outcome.pages]


def test_crawl_skips_non_html_and_error_pages() -> None:
    transport = ScriptedTransport()
    route(transport, "/", "<a href='/data.json'>j</a><a href='/gone'>g</a>")
    route(transport, ".json", '{"a":1}', content_type="application/json")
    route(transport, "/gone", "not found", status=404)

    outcome = crawl_site(transport, depth=1)

    assert outcome.stats.pages_fetched == 3
    for page in outcome.pages:
        if page.url.endswith((".json", "/gone")):
            assert page.links == ()
            assert page.forms == ()


def test_crawl_records_form_and_parameter_counts() -> None:
    transport = ScriptedTransport()
    route(
        transport,
        "/",
        '<form method="post" action="/search">'
        '<input name="q"><input name="page"></form>',
    )

    outcome = crawl_site(transport)

    assert outcome.stats.forms_discovered == 1
    assert outcome.stats.parameters_found == 2


def test_crawl_counts_seed_query_names_once() -> None:
    """The seed's own parameters are real points; duplicates are not."""
    transport = ScriptedTransport()
    route(transport, "/?id=2", "<p>next</p>")
    route(transport, "/?id=1", "<a href='/?id=2'>next</a>")

    outcome = crawl(
        "https://example.com/?id=1&sort=asc",
        transport=transport,
        scope=Scope(["example.com"]),
        deny=DenyList(),
        settings=settings(),
    )

    assert outcome.stats.parameters_found == 2


def test_crawl_propagates_budget_exhaustion() -> None:
    transport = ScriptedTransport()
    route(transport, "/", "<a href='/a'>a</a>")

    with pytest.raises(BudgetExceeded):
        crawl(
            "https://example.com/",
            transport=transport,
            scope=Scope(["example.com"]),
            deny=DenyList(),
            budget=RequestBudget(1),
            settings=settings(depth=1),
        )


def test_robots_is_fetched_and_respected_when_enabled() -> None:
    transport = ScriptedTransport()
    route(transport, "/robots.txt", "User-agent: *\nDisallow: /private\n")
    route(transport, "/", "<a href='/private/x'>p</a><a href='/public'>q</a>")
    route(transport, "/public", "ok")

    outcome = crawl_site(transport, depth=1, respect_robots=True)

    assert outcome.stats.robots_disallowed == 1
    assert "https://example.com/robots.txt" in transport.urls


def test_robots_fetch_failure_does_not_stop_the_crawl() -> None:
    transport = ScriptedTransport()

    def boom(request: Request) -> object:
        raise TransportError("connection reset")

    transport.add(lambda request: request.url.endswith("/robots.txt"), boom)  # type: ignore[arg-type]

    assert crawl_site(transport, respect_robots=True).stats.pages_fetched == 1


def test_robots_non_200_is_treated_as_absent() -> None:
    transport = ScriptedTransport()
    route(transport, "/robots.txt", "nope", status=404)
    assert crawl_site(transport, respect_robots=True).stats.robots_disallowed == 0


def test_crawl_reports_the_url_that_answered_after_a_redirect() -> None:
    transport = ScriptedTransport()
    transport.add(
        lambda request: request.url == "https://example.com/",
        lambda _request: response("https://example.com/home", "ok"),
    )

    outcome = crawl_site(transport)

    assert outcome.seed == "https://example.com/home"
    assert outcome.pages[0].url == "https://example.com/home"


def test_form_serialises_for_the_report() -> None:
    form = Form(
        action="/login",
        method=Method.POST,
        fields=(("user", "bob"),),
        has_file=True,
    )
    payload = form.to_dict()
    assert payload["action"] == "/login"
    assert payload["method"] == "POST"
    assert payload["fields"] == [["user", "bob"]]
    assert payload["has_file"] is True


def test_parse_page_ignores_an_empty_href() -> None:
    _base, links, _forms = parse_page('<a href="">x</a><a href="/real">y</a>')
    assert links == ("/real",)


def test_parse_page_returns_what_it_had_when_the_parser_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed document truncates the parse; it never aborts the crawl."""
    from sqliscan.crawl import _PageParser  # noqa: PLC0415 - internal, test only

    def boom(self: _PageParser, _data: str) -> None:
        raise RuntimeError("parser exploded")

    monkeypatch.setattr(_PageParser, "feed", boom)
    assert parse_page("<a href='/a'>a</a>") == (None, (), ())


def test_robots_failure_to_parse_a_url_is_treated_as_allowed() -> None:
    class Exploding:
        def can_fetch(self, _agent: str, _url: str) -> bool:
            raise ValueError("bad url")

    allowed = robots_allows(Exploding(), "sqliscan", "https://example.com/")  # type: ignore[arg-type]
    assert allowed is True


def test_a_link_already_queued_is_not_queued_twice() -> None:
    transport = ScriptedTransport()
    route(transport, "/a", "<a href='/x'>x</a>")
    route(transport, "/b", "<a href='/x'>x</a>")
    route(transport, "/", "<a href='/a'>a</a><a href='/b'>b</a>")
    route(transport, "/x", "ok")

    outcome = crawl_site(transport, depth=2)

    assert transport.urls.count("https://example.com/x") == 1
    assert outcome.stats.pages_fetched == 4
