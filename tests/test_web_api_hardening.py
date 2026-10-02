"""Web/API hardening depth (#244): CORS origin policy, GraphQL limits and
batching, CSRF inference for cookie-session auth."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.models import Route, ScanResult, WebHardeningIssue
from attackmap.scanner import scan_repo
from attackmap.taxonomy import taxonomy_for
from attackmap.threat_model import generate_findings
from attackmap.weaknesses import find_code_weaknesses
from attackmap.webhardening import find_web_hardening_issues, has_csrf_protection


def _issues(content: str, name: str = "app.js") -> dict[str, str]:
    """kind -> severity."""
    return {i.kind: i.severity for i in find_web_hardening_issues(content, name)}


# ---------------------------------------------------------------------------
# CORS: origin_policy x credentials
# ---------------------------------------------------------------------------

CREDS_JS = "app.use(cors({ credentials: true }))\n"


@pytest.mark.parametrize(
    "content",
    [
        # reflected: the request's Origin echoed back
        "res.setHeader('Access-Control-Allow-Origin', req.headers.origin)\n"
        "res.setHeader('Access-Control-Allow-Credentials', 'true')\n",
        "res.header('Access-Control-Allow-Origin', req.header('origin'));\n"
        "res.header('Access-Control-Allow-Credentials', true);\n",
        'response["Access-Control-Allow-Origin"] = request.headers.get("Origin")\n'
        'response["Access-Control-Allow-Credentials"] = "true"\n',
        # reflected: an origin callback that accepts everything
        "app.use(cors({ origin: (origin, cb) => cb(null, true), credentials: true }))\n",
        "app.use(cors({ credentials: true, origin: function (o, callback) { callback(null, true) } }))\n",
        # wildcard spellings
        'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n',
        "CORS_ALLOW_ALL_ORIGINS = True\nCORS_ALLOW_CREDENTIALS = True\n",
        "CORS_ORIGIN_ALLOW_ALL = True\nCORS_ALLOW_CREDENTIALS = True\n",
    ],
)
def test_reflected_or_wildcard_origin_with_credentials_is_high(content: str) -> None:
    assert _issues(content).get("cors_wildcard_credentials") == "high"


@pytest.mark.parametrize(
    "content",
    [
        "res.setHeader('Access-Control-Allow-Origin', '*')\n",
        "res.setHeader('Access-Control-Allow-Origin', req.headers.origin)\n",
        "CORS_ALLOW_ALL_ORIGINS = True\n",
    ],
)
def test_wildcard_without_credentials_is_informational(content: str) -> None:
    issues = _issues(content)
    assert issues.get("cors_wildcard_origin") == "low"
    assert "cors_wildcard_credentials" not in issues


@pytest.mark.parametrize(
    "content",
    [
        "if (allowed.includes(req.headers.origin)) {\n"
        "  res.setHeader('Access-Control-Allow-Origin', req.headers.origin)\n}\n",
        "const ok = ALLOWED.has(req.headers.origin)\n"
        "if (ok) res.setHeader('Access-Control-Allow-Origin', req.headers.origin)\n",
        "app.use(cors({ origin: (o, cb) => ALLOWED.includes(o) ? cb(null, true) : cb(new Error('x')) }))\n",
    ],
)
def test_guarded_reflection_is_not_flagged(content: str) -> None:
    issues = _issues(content + CREDS_JS)
    assert "cors_wildcard_credentials" not in issues
    assert "cors_wildcard_origin" not in issues


@pytest.mark.parametrize(
    ("content", "policy"),
    [
        ("app.use(cors({ origin: /example\\.com/, credentials: true }))\n", "regex_unanchored"),
        ("app.use(cors({ origin: [/example\\.com$/], credentials: true }))\n", "regex_unanchored"),
        ("app.use(cors({ origin: [/^https:\\/\\/.*example\\.com$/], credentials: true }))\n", "regex_unanchored"),
        ("CORS_ALLOWED_ORIGIN_REGEXES = [r'^https://\\w+\\.example\\.com']\nCORS_ALLOW_CREDENTIALS = True\n", "regex_unanchored"),
        ('app.add_middleware(CORSMiddleware, allow_origin_regex="https://.*example\\.com", allow_credentials=True)\n', "regex_unanchored"),
        ("if (origin.endsWith('example.com')) cb(null, true)\n" + CREDS_JS, "suffix_match"),
        ("if (requestOrigin.includes('example.com')) allow()\n" + CREDS_JS, "suffix_match"),
        ('if origin.endswith("example.com"):\n    allow()\nsupports_credentials=True\n', "suffix_match"),
        ("app.use(cors({ origin: ['https://app.example.com', 'null'], credentials: true }))\n", "null_allowed"),
        ("CORS_ALLOWED_ORIGINS = ['https://app.example.com', 'null']\nCORS_ALLOW_CREDENTIALS = True\n", "null_allowed"),
    ],
)
def test_untrusted_origin_policies_with_credentials_are_high(content: str, policy: str) -> None:
    assert _issues(content).get("cors_untrusted_origin") == "high", policy


def test_untrusted_origin_without_credentials_is_medium() -> None:
    assert _issues("app.use(cors({ origin: /example\\.com/ }))\n").get("cors_untrusted_origin") == "medium"


@pytest.mark.parametrize(
    "content",
    [
        # exact allow-lists
        "app.use(cors({ origin: ['https://app.example.com', 'https://admin.example.com'], credentials: true }))\n",
        "app.use(cors({ origin: 'https://app.example.com', credentials: true }))\n",
        "CORS_ALLOWED_ORIGINS = ['https://app.example.com']\nCORS_ALLOW_CREDENTIALS = True\n",
        # anchored regexes
        "app.use(cors({ origin: [/^https:\\/\\/app\\.example\\.com$/], credentials: true }))\n",
        "app.use(cors({ origin: [/\\.example\\.com$/], credentials: true }))\n",
        "CORS_ALLOWED_ORIGIN_REGEXES = [r'^https://\\w+\\.example\\.com$']\nCORS_ALLOW_CREDENTIALS = True\n",
        # Starlette full-matches, so a missing `$` is fine there
        'app.add_middleware(CORSMiddleware, allow_origin_regex="https://[a-z]+\\.example\\.com", allow_credentials=True)\n',
        # sound subdomain check
        "if (origin.endsWith('.example.com')) cb(null, true)\n" + CREDS_JS,
        # not origin checks
        "if (originalUrl.includes('example.com')) next()\n",
        "const x = { origin: 'null-island' }\n",
    ],
)
def test_anchored_or_exact_allow_lists_produce_no_cors_finding(content: str) -> None:
    issues = _issues(content)
    assert not {"cors_untrusted_origin", "cors_wildcard_credentials", "cors_wildcard_origin"} & set(issues)


def test_cors_finding_severity_follows_its_instances() -> None:
    scan = ScanResult(
        root="/",
        web_hardening_issues=[
            WebHardeningIssue(kind="cors_untrusted_origin", file="a.js", line=1, severity="medium"),
            WebHardeningIssue(kind="cors_untrusted_origin", file="b.js", line=2, severity="high"),
            WebHardeningIssue(kind="cors_wildcard_origin", file="c.js", line=3, severity="low"),
        ],
    )
    by_rule = {f.rule_id: f for f in generate_findings(scan)}
    assert by_rule["cors-untrusted-origin"].severity == "high"
    assert by_rule["cors-untrusted-origin"].taxonomy.cwe == ["CWE-346", "CWE-942"]
    assert by_rule["cors-wildcard-origin"].severity == "low"


# ---------------------------------------------------------------------------
# GraphQL: depth/complexity limits and batching
# ---------------------------------------------------------------------------

APOLLO = (
    "const { ApolloServer } = require('@apollo/server')\n"
    "const server = new ApolloServer({\n"
    "  typeDefs,\n"
    "  resolvers,\n"
    "{extra}"
    "})\n"
)


def _gql(content: str, name: str = "server.js") -> dict[str, str]:
    return {w.kind: w.severity for w in find_code_weaknesses(content, name)}


def test_apollo_without_depth_limit_and_with_batching_is_flagged() -> None:
    kinds = _gql(APOLLO.replace("{extra}", "  allowBatchedHttpRequests: true,\n"))
    assert kinds["graphql_no_query_limits"] == "low"
    assert kinds["graphql_batching"] == "medium"


def test_apollo_with_graphql_depth_limit_is_not_flagged() -> None:
    content = "const depthLimit = require('graphql-depth-limit')\n" + APOLLO.replace(
        "{extra}", "  validationRules: [depthLimit(10)],\n"
    )
    kinds = _gql(content)
    assert "graphql_no_query_limits" not in kinds
    assert "graphql_batching" not in kinds


@pytest.mark.parametrize(
    ("content", "name"),
    [
        ("schema = strawberry.Schema(query=Query)\n", "schema.py"),
        ("app.use('/graphql', graphqlHTTP({ schema, graphiql: false }))\n", "app.js"),
        ("srv := handler.NewDefaultServer(generated.NewExecutableSchema(cfg))\n", "server.go"),
        ("path('graphql', GraphQLView.as_view(schema=schema))\n", "urls.py"),
    ],
)
def test_other_servers_without_limits_are_flagged(content: str, name: str) -> None:
    assert "graphql_no_query_limits" in _gql(content, name)


@pytest.mark.parametrize(
    ("content", "name"),
    [
        ("schema = strawberry.Schema(query=Query, extensions=[QueryDepthLimiter(max_depth=10)])\n", "schema.py"),
        (
            "srv := handler.NewDefaultServer(generated.NewExecutableSchema(cfg))\n"
            "srv.Use(extension.FixedComplexityLimit(200))\n",
            "server.go",
        ),
        ("const yoga = createYoga({ schema, plugins: [EnvelopArmorPlugin()] }) // graphql-armor\n", "yoga.ts"),
    ],
)
def test_servers_with_limits_are_not_flagged(content: str, name: str) -> None:
    assert "graphql_no_query_limits" not in _gql(content, name)


def test_files_without_a_graphql_server_are_ignored() -> None:
    assert not {"graphql_no_query_limits", "graphql_batching"} & set(_gql("const batching = { batching: true }\n"))


def test_graphql_rules_are_registered() -> None:
    for rule in ("graphql-no-query-limits", "graphql-batching"):
        entry = taxonomy_for(rule)
        assert entry is not None and "API4:2023" in entry.owasp


# ---------------------------------------------------------------------------
# CSRF inference: cookie-session auth + mutating routes + no CSRF defence
# ---------------------------------------------------------------------------

EXPRESS_SESSION_APP = (
    "const express = require('express')\n"
    "const session = require('express-session')\n"
    "const app = express()\n"
    "app.use(session({ secret: process.env.SESSION_SECRET, resave: false }))\n"
    "app.post('/transfer', (req, res) => { res.send('ok') })\n"
    "app.listen(3000)\n"
)


def _csrf_findings(tmp_path: Path) -> list:
    scan = scan_repo(tmp_path)
    return [f for f in generate_findings(scan) if f.rule_id == "csrf-unprotected-session"]


def test_express_session_with_post_route_and_no_csrf_is_medium(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(EXPRESS_SESSION_APP, encoding="utf-8")
    (finding,) = _csrf_findings(tmp_path)
    assert finding.severity == "medium"
    assert finding.taxonomy.cwe == ["CWE-352"]
    assert "app.js:2" in finding.evidence[0]


@pytest.mark.parametrize(
    "extra",
    [
        "const { doubleCsrf } = require('csrf-csrf')\n",
        "const csrf = require('csurf')\napp.use(csrf())\n",
        "app.use(session({ cookie: { sameSite: 'strict' } }))\n",
    ],
)
def test_csrf_defence_in_the_same_file_clears_it(tmp_path: Path, extra: str) -> None:
    (tmp_path / "app.js").write_text(EXPRESS_SESSION_APP + extra, encoding="utf-8")
    assert _csrf_findings(tmp_path) == []


def test_csrf_defence_in_another_file_clears_it(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(EXPRESS_SESSION_APP, encoding="utf-8")
    (tmp_path / "csrf.js").write_text("module.exports = require('csurf')({ cookie: true })\n", encoding="utf-8")
    assert _csrf_findings(tmp_path) == []


def test_session_without_state_changing_routes_is_not_flagged() -> None:
    issue = WebHardeningIssue(kind="csrf_unprotected_session", file="app.js", line=2, severity="medium")
    read_only = ScanResult(root="/", web_hardening_issues=[issue], routes=[Route(path="/", method="GET", file="app.js")])
    assert not [f for f in generate_findings(read_only) if f.rule_id == "csrf-unprotected-session"]
    mutating = read_only.model_copy(update={"routes": [Route(path="/t", method="POST", file="app.js")]})
    assert [f for f in generate_findings(mutating) if f.rule_id == "csrf-unprotected-session"]


def test_django_settings_with_csrf_middleware_commented_out_is_a_candidate() -> None:
    settings = (
        "MIDDLEWARE = [\n"
        "    'django.contrib.sessions.middleware.SessionMiddleware',\n"
        "    # 'django.middleware.csrf.CsrfViewMiddleware',\n"
        "]\n"
    )
    assert "csrf_unprotected_session" in _issues(settings, "settings.py")
    enabled = settings.replace("    # 'django", "    'django")
    assert "csrf_unprotected_session" not in _issues(enabled, "settings.py")


def test_has_csrf_protection_ignores_comments() -> None:
    assert not has_csrf_protection("// app.use(csrf())\n# CSRFProtect(app)\n")
    assert has_csrf_protection("CSRFProtect(app)\n")
