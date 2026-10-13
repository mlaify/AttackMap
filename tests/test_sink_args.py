"""Sinks count request data only in their dangerous argument (#375).

The legacy same-call token gate read the whole call, so request data in a
harmless argument raised the sink: `getattr(request.user, 'name')` (the
object, not the attribute name), `re.split(r'…', request.GET['q'])` (the
subject, not the pattern). And a redirect to `reverse("view")` /
`url_for("view")` goes to an internal path whatever the request adds as
kwargs or query.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.models import Route, ScanResult
from attackmap.taint import analyze_taint


def _kinds(tmp_path: Path, body: str) -> set[str]:
    (tmp_path / "views.py").write_text(
        "import re\n"
        "from django.shortcuts import redirect\n"
        "from django.urls import reverse\n"
        "from flask import url_for\n\n\n"
        "def view(request):\n"
        f"    {body}\n",
        encoding="utf-8",
    )
    scan = ScanResult(root=str(tmp_path), routes=[Route(path="/v", method="GET", file="views.py", line=7)])
    return {c.sink_kind for c in analyze_taint(scan, tmp_path) if not c.sanitized}


@pytest.mark.parametrize(
    "body, kind",
    [
        ("return getattr(request.user, 'ldap_username', None)", "code_injection"),
        ("return getattr(request, 'session', None)", "code_injection"),
        (r"return re.split(r'\s*[,;]\s*', request.GET['q'].strip())", "regex_injection"),
        (r"return re.match(r'^[a-z0-9-]+$', request.POST['name'])", "regex_injection"),
        ("return redirect(reverse(remote_user_sso, query=request.GET))", "open_redirect"),
        ("return redirect(reverse('home') + '?next=' + request.GET['n'])", "open_redirect"),
        ("return redirect(url_for('index', q=request.args['q']))", "open_redirect"),
        ("return redirect(f\"{reverse('home')}?q={request.GET['q']}\")", "open_redirect"),
    ],
)
def test_request_data_outside_the_dangerous_argument_is_not_a_sink(tmp_path: Path, body: str, kind: str) -> None:
    assert kind not in _kinds(tmp_path, body)


@pytest.mark.parametrize(
    "body, kind",
    [
        ("return getattr(handlers, request.GET['action'])()", "code_injection"),
        ("return re.compile(request.GET['pattern'])", "regex_injection"),
        ("return re.search(request.GET['p'], 'text')", "regex_injection"),
        ("return redirect(request.GET['next'])", "open_redirect"),
        ("return redirect(request.GET.get('next', reverse('home')))", "open_redirect"),
        ("return redirect(build(reverse('home'), request.GET['n']))", "open_redirect"),
    ],
)
def test_request_data_in_the_dangerous_argument_is_still_a_sink(tmp_path: Path, body: str, kind: str) -> None:
    assert kind in _kinds(tmp_path, body)
