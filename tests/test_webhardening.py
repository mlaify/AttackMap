"""Tests for web-hardening gap detection (#71)."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.models import ScanResult, WebHardeningIssue
from attackmap.scanner import scan_repo
from attackmap.threat_model import generate_findings
from attackmap.webhardening import find_web_hardening_issues


def _kinds(content: str) -> set[str]:
    return {i.kind for i in find_web_hardening_issues(content, "f.py")}


# ---------------------------------------------------------------------------
# CORS wildcard + credentials (two-part co-occurrence)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "CORS(app, origins='*', supports_credentials=True)\n",
        "app.use(cors({ origin: '*', credentials: true }))\n",
        "app.use(cors({ origin: true, credentials: true }))\n",  # reflected
        (
            "res.setHeader('Access-Control-Allow-Origin', '*')\n"
            "res.setHeader('Access-Control-Allow-Credentials', 'true')\n"
        ),
    ],
)
def test_cors_wildcard_with_credentials_flagged(content: str) -> None:
    assert "cors_wildcard_credentials" in _kinds(content)


def test_wildcard_cors_without_credentials_not_flagged() -> None:
    # Wildcard origin alone (no credentials) is a common, acceptable public-API config.
    content = "res.setHeader('Access-Control-Allow-Origin', '*')\n"
    assert "cors_wildcard_credentials" not in _kinds(content)


def test_specific_origin_with_credentials_not_flagged() -> None:
    content = "app.use(cors({ origin: 'https://app.example.com', credentials: true }))\n"
    assert "cors_wildcard_credentials" not in _kinds(content)


# ---------------------------------------------------------------------------
# CSRF disabled
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "@csrf_exempt\ndef view(request): ...\n",
        "WTF_CSRF_ENABLED = False\n",
        "http.csrf().disable();\n",
        "http.csrf(csrf -> csrf.disable());\n",
        "app.use(csurf({ csrf: false }))\n",
        "http {\n    csrf { disable() }\n}\n",  # Spring Security Kotlin DSL (#341)
        "http { csrf {disable()} }\n",
    ],
)
def test_csrf_disabled_flagged(content: str) -> None:
    assert "csrf_disabled" in _kinds(content)


@pytest.mark.parametrize(
    "content",
    [
        'http {\n    csrf { ignoringRequestMatchers("/webhooks/**") }\n}\n',
        "http {\n    csrf { }\n}\n",
        "val disableCsrf = false\n",
    ],
)
def test_kotlin_csrf_configuration_without_disable_not_flagged(content: str) -> None:
    assert "csrf_disabled" not in _kinds(content)


# ---------------------------------------------------------------------------
# Spring Security config in Java / Kotlin (#341): a whole-repo pass, since the
# per-file scan doesn't read .java/.kt files.
# ---------------------------------------------------------------------------

_KOTLIN_CONFIG = """package demo

@Configuration
class SecurityConfig {
    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            csrf { disable() }
            authorizeHttpRequests { authorize(anyRequest, authenticated) }
        }
        return http.build()
    }
}
"""

_JAVA_CONFIG = """@Configuration
public class WebSecurityConfig {
  @Bean
  SecurityFilterChain chain(HttpSecurity http) throws Exception {
    return http.csrf(csrf -> csrf.disable()).build();
  }
}
"""


def _csrf_issues(tmp_path: Path) -> list[WebHardeningIssue]:
    return [i for i in scan_repo(tmp_path).web_hardening_issues if i.kind == "csrf_disabled"]


def test_kotlin_dsl_csrf_disable_in_a_kt_file(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "SecurityConfig.kt").write_text(_KOTLIN_CONFIG, encoding="utf-8")
    [issue] = _csrf_issues(tmp_path)
    assert (issue.file, issue.line, issue.severity) == ("src/SecurityConfig.kt", 8, "medium")
    assert "csrf-disabled" in {f.rule_id for f in generate_findings(scan_repo(tmp_path))}


def test_java_csrf_disable_in_a_java_file(tmp_path: Path) -> None:
    (tmp_path / "WebSecurityConfig.java").write_text(_JAVA_CONFIG, encoding="utf-8")
    [issue] = _csrf_issues(tmp_path)
    assert issue.line == 5


def test_kotlin_ignoring_matchers_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "SecurityConfig.kt").write_text(
        _KOTLIN_CONFIG.replace("csrf { disable() }", 'csrf { ignoringRequestMatchers("/webhooks/**") }'),
        encoding="utf-8",
    )
    assert _csrf_issues(tmp_path) == []


def test_commented_out_disable_and_test_code_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "SecurityConfig.kt").write_text(
        _KOTLIN_CONFIG.replace("csrf { disable() }", "// csrf { disable() }"), encoding="utf-8"
    )
    tests = tmp_path / "src" / "test" / "kotlin"
    tests.mkdir(parents=True)
    (tests / "TestSecurityConfig.kt").write_text(_KOTLIN_CONFIG, encoding="utf-8")
    assert _csrf_issues(tmp_path) == []


def test_stateless_token_api_is_reported_low(tmp_path: Path) -> None:
    (tmp_path / "SecurityConfig.java").write_text(
        _JAVA_CONFIG.replace(
            "return http.csrf",
            "http.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));\n    return http.csrf",
        ),
        encoding="utf-8",
    )
    [issue] = _csrf_issues(tmp_path)
    assert issue.severity == "low"
    assert "stateless session policy" in (issue.evidence_text or "")


# ---------------------------------------------------------------------------
# Insecure cookies
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "res.cookie('sid', v, { httpOnly: false })\n",
        "res.cookie('sid', v, { secure: false })\n",
        "res.cookie('sid', v, { sameSite: 'none' })\n",
        "SESSION_COOKIE_SECURE = False\n",
        "SESSION_COOKIE_HTTPONLY = False\n",
    ],
)
def test_insecure_cookie_flagged(content: str) -> None:
    assert "insecure_cookie" in _kinds(content)


def test_samesite_none_with_secure_not_flagged_by_raw_header() -> None:
    # `SameSite=None; Secure` is the correct cross-site cookie config.
    content = "Set-Cookie: sid=x; SameSite=None; Secure\n"
    assert "insecure_cookie" not in _kinds(content)


# ---------------------------------------------------------------------------
# Weak CSP
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "csp = \"default-src 'self'; script-src 'unsafe-inline'\"\n",
        "\"Content-Security-Policy\": \"script-src 'unsafe-eval'\"\n",
    ],
)
def test_weak_csp_flagged(content: str) -> None:
    assert "weak_csp" in _kinds(content)


def test_strict_csp_not_flagged() -> None:
    content = "csp = \"default-src 'self'; script-src 'self'\"\n"
    assert "weak_csp" not in _kinds(content)


# ---------------------------------------------------------------------------
# Debug enabled
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "app.run(host='0.0.0.0', debug=True)\n",
        "DEBUG = True\n",
        "management.endpoints.web.exposure.include=*\n",
        "config.consider_all_requests_local = true\n",
    ],
)
def test_debug_enabled_flagged(content: str) -> None:
    assert "debug_enabled" in _kinds(content)


def test_debug_false_not_flagged() -> None:
    assert "debug_enabled" not in _kinds("DEBUG = False\napp.run(debug=False)\n")


# ---------------------------------------------------------------------------
# Metadata + dedup
# ---------------------------------------------------------------------------


def test_issue_carries_metadata() -> None:
    issue = find_web_hardening_issues("SESSION_COOKIE_SECURE = False\n", "settings.py")[0]
    assert issue.file == "settings.py"
    assert issue.line == 1
    assert issue.severity == "medium"
    assert issue.source_analyzer == "webhardening"


# ---------------------------------------------------------------------------
# Findings via threat_model
# ---------------------------------------------------------------------------


def test_cors_finding_high_with_technique() -> None:
    scan = ScanResult(
        root="/",
        web_hardening_issues=[
            WebHardeningIssue(kind="cors_wildcard_credentials", file="app.py", line=5, severity="high")
        ],
    )
    findings = [f for f in generate_findings(scan) if "web-hardening" in f.tags]
    assert findings
    assert findings[0].severity == "high"
    assert findings[0].attack_techniques[0].technique_id == "T1539"


def test_distinct_kinds_yield_distinct_findings() -> None:
    scan = ScanResult(
        root="/",
        web_hardening_issues=[
            WebHardeningIssue(kind="debug_enabled", file="a.py", line=1, severity="medium"),
            WebHardeningIssue(kind="weak_csp", file="b.py", line=2, severity="medium"),
        ],
    )
    titles = {f.title for f in generate_findings(scan) if "web-hardening" in f.tags}
    assert any("Debug" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)


# ---------------------------------------------------------------------------
# End-to-end via scan_repo
# ---------------------------------------------------------------------------


def test_scan_repo_populates_web_hardening(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "if __name__ == '__main__':\n"
        "    app.run(host='0.0.0.0', debug=True)\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert any(i.kind == "debug_enabled" for i in scan.web_hardening_issues)
    assert [f for f in generate_findings(scan) if "web-hardening" in f.tags]


def test_scan_repo_clean_config_no_web_findings(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text(
        "DEBUG = False\n"
        "SESSION_COOKIE_SECURE = True\n"
        "SESSION_COOKIE_HTTPONLY = True\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert scan.web_hardening_issues == []


# ---------------------------------------------------------------------------
# #341 review: comments, strings and context
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("block.java", "class C {\n  /*\n   * http.csrf().disable();\n   */\n  void f() {}\n}\n"),
        ("trailing.java", "class C {\n  void f(HttpSecurity http) { http.cors(); // was: .csrf().disable()\n  }\n}\n"),
        ("string.java", 'class C {\n  String doc = "call http.csrf().disable() to turn it off";\n}\n'),
        ("textblock.kt", 'val doc = """\n  http { csrf { disable() } }\n"""\n'),
        ("nested.kt", "/* outer /* inner */ http { csrf { disable() } } */\nval x = 1\n"),
        ("unrelated.kt", "fun build() {\n    myDsl {\n        csrf { disable() }\n    }\n}\n"),
        ("toplevel.kt", "fun f() = csrf { disable() }\n"),
    ],
)
def test_jvm_csrf_ignores_comments_strings_and_unrelated_dsls(tmp_path: Path, name: str, text: str) -> None:
    (tmp_path / name).write_text(text, encoding="utf-8")
    assert _csrf_issues(tmp_path) == []


@pytest.mark.parametrize(
    ("text", "line"),
    [
        ("@Bean\nfun chain(http: HttpSecurity): SecurityFilterChain {\n    http.csrf { it.disable() }\n    return http.build()\n}\n", 3),
        ("fun chain(http: HttpSecurity) {\n    http.csrf { c -> c.disable() }\n}\n", 2),
        (
            "fun chain(http: ServerHttpSecurity) = http {\n"
            "    authorizeExchange { authorize(anyExchange, authenticated) }\n"
            "    csrf { disable() }\n"
            "}\n",
            3,
        ),
        ("fun chain(http: HttpSecurity) {\n    http.invoke {\n        csrf { disable() }\n    }\n}\n", 3),
    ],
)
def test_kotlin_forms_in_a_security_context(tmp_path: Path, text: str, line: int) -> None:
    (tmp_path / "Security.kt").write_text(text, encoding="utf-8")
    [issue] = _csrf_issues(tmp_path)
    assert issue.line == line


def test_stateless_policy_elsewhere_in_the_file_does_not_downgrade(tmp_path: Path) -> None:
    far = "\n" * 40
    (tmp_path / "SecurityConfig.java").write_text(
        _JAVA_CONFIG + far + "class Other { void f(HttpSecurity h) { h.sessionManagement(s -> "
        "s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); } }\n",
        encoding="utf-8",
    )
    [issue] = _csrf_issues(tmp_path)
    assert issue.severity == "medium"


def test_stateless_policy_in_the_same_chain_far_below_still_downgrades(tmp_path: Path) -> None:
    chain = "    http.csrf(csrf -> csrf.disable())\n" + "      .cors(c -> {})\n" * 40
    chain += "      .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));\n"
    (tmp_path / "Sec.java").write_text("class Sec {\n  void f(HttpSecurity http) {\n" + chain + "  }\n}\n", encoding="utf-8")
    [issue] = _csrf_issues(tmp_path)
    assert issue.severity == "low"


def test_kotlin_dsl_stateless_in_the_same_block(tmp_path: Path) -> None:
    (tmp_path / "Sec.kt").write_text(
        "fun f(http: HttpSecurity) {\n    http {\n        csrf { disable() }\n"
        "        sessionManagement { sessionCreationPolicy = SessionCreationPolicy.STATELESS }\n    }\n}\n",
        encoding="utf-8",
    )
    [issue] = _csrf_issues(tmp_path)
    assert issue.severity == "low"


def test_masking_keeps_offsets_and_never_raises() -> None:
    import random

    from attackmap.webhardening import mask_jvm_comments_and_strings

    text = 'a /* b "c" */ d // e\n"f\\"g" \'h\' """i\nj""" k'
    masked = mask_jvm_comments_and_strings(text)
    assert len(masked) == len(text) and masked.count("\n") == text.count("\n")
    from attackmap.webhardening import _Blocks

    def naive(text: str, offset: int) -> int:
        # Reference: innermost block whose span contains the offset.
        blocks = _Blocks(text)
        inside = [i for i in range(len(blocks.opens)) if blocks.opens[i] < offset < blocks.closes[i]]
        return max(inside, key=lambda i: blocks.opens[i]) if inside else -1

    samples = ["", "}", "{", "{{}}}", "a { b { c } d", "}{}{{}", "a { b { c } d } e"]
    rng = random.Random(360)
    samples += ["".join(rng.choice("{}ab") for _ in range(rng.randint(0, 25))) for _ in range(300)]
    for sample in samples:
        offsets = list(range(len(sample) + 1))
        got = _Blocks(sample).innermost_each(offsets)
        assert got == [naive(sample, o) for o in offsets], sample
    blocks = _Blocks("a { b { c } d } e")
    assert blocks.innermost_each([8, 12, 16]) == [1, 0, -1]
    assert masked.split() == ["a", "d", "k"]
    rng = random.Random(341)
    alphabet = "/*\"'\\\n ab{}"
    for _ in range(2000):
        sample = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 30)))
        out = mask_jvm_comments_and_strings(sample)
        assert len(out) == len(sample)


def test_java_comments_do_not_nest(tmp_path: Path) -> None:
    # `/api/**` inside a Javadoc must not open a second comment level and
    # mask the rest of the file.
    (tmp_path / "Sec.java").write_text(
        "class Sec {\n  /** Permits /api/** without login. */\n"
        "  void f(HttpSecurity http) { http.csrf().disable(); }\n}\n",
        encoding="utf-8",
    )
    [issue] = _csrf_issues(tmp_path)
    assert issue.line == 3


def test_kotlin_comments_nest(tmp_path: Path) -> None:
    (tmp_path / "Sec.kt").write_text(
        "/* a /* b */ http { csrf { disable() } } */\n"
        "fun f(http: HttpSecurity) {\n    http { csrf { disable() } }\n}\n",
        encoding="utf-8",
    )
    [issue] = _csrf_issues(tmp_path)
    assert issue.line == 3


def test_jvm_csrf_pass_is_linear_on_large_files() -> None:
    import time

    from attackmap.webhardening import _jvm_csrf_issues

    # ~760 KB with thousands of matches in ONE block: walking back (or
    # forward) through the block per match was quadratic.
    body = "fun f(http: HttpSecurity) {\n    http {\n" + "        csrf { disable() }\n" * 28_000 + "    }\n}\n"
    start = time.perf_counter()
    assert len(_jvm_csrf_issues(body, "Big.kt")) == 28_000
    assert time.perf_counter() - start < 5.0
    # Deep nesting closed just before many matches (and a stateless policy
    # in the method, so each match needs its block): walking the parents
    # per match was quadratic.
    deep = "class C {\n  void f(HttpSecurity h) {\n    " + "{" * 20_000 + "}" * 20_000 + "\n"
    deep += "    h.csrf().disable();\n" * 20_000
    deep += "    h.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));\n  }\n}\n"
    start = time.perf_counter()
    issues = _jvm_csrf_issues(deep, "Deep.java")
    assert len(issues) == 20_000 and all(i.severity == "low" for i in issues)
    assert time.perf_counter() - start < 3.0
    # Many stateless policies and many matches: checking every policy per
    # match was quadratic.
    many = "class C {\n" + (
        "  void f(HttpSecurity h) { h.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); }\n"
    ) * 16_000 + "  void g(HttpSecurity h) {\n" + "    h.csrf().disable();\n" * 30_000 + "  }\n}\n"
    start = time.perf_counter()
    issues = _jvm_csrf_issues(many, "Many.java")
    assert len(issues) == 30_000 and all(i.severity == "medium" for i in issues)
    assert time.perf_counter() - start < 3.0
    java = "class C {\n  void f(HttpSecurity h) {\n" + "    h.csrf().disable();\n" * 30_000
    java += "    h.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));\n  }\n}\n"
    start = time.perf_counter()
    issues = _jvm_csrf_issues(java, "Big.java")
    assert len(issues) == 30_000 and all(i.severity == "low" for i in issues)
    assert time.perf_counter() - start < 5.0
