"""A Python URLconf route starts its taint walk at its own view (#372).

`urls.py` imports every view module, so walking from it gave every route
every view's sinks at hop 1 (zulip: 95 routes reaching one view's
`cursor.execute`). A registration that names its view now seeds the walk from
that view's module, limited at hop 0 to the view's own def/class. A
third-party view (`TemplateView.as_view()`) runs no repo code, and an unknown
handler falls back to walking from the URLconf.
"""

from __future__ import annotations

import random
from pathlib import Path

from attackmap.models import Route, ScanResult
from attackmap.taint import _py_bindings, _py_def_span, _py_urlconf_seeds, analyze_taint

_VIEWS = (
    "import subprocess\n"
    "from django.http import HttpResponse\n\n\n"
    "def report(request):\n"
    "    subprocess.run('report ' + request.GET['id'], shell=True)\n"  # 6
    "    return HttpResponse('ok')\n\n\n"
    "class Export:\n"  # 10
    "    def get(self, request):\n"
    "        subprocess.run('export ' + request.GET['k'], shell=True)\n"  # 12
    "        return HttpResponse('ok')\n"  # 13
)
_BILLING = "from django.http import HttpResponse\n\n\ndef billing_page(request):\n    return HttpResponse('billing')\n"
_URLS = (
    "from django.urls import include, path\n"
    "from django.views.generic import TemplateView\n\n"
    "from shop.billing import billing_page\n"
    "from shop.views import Export, report\n\n\n"
    "def local_view(request):\n"
    "    return None\n\n\n"
    "urlpatterns = [\n"
    "    path('billing/', billing_page, name='billing'),\n"  # 13
    "    path('report/', report),\n"  # 14
    "    path('export/', Export.as_view()),\n"  # 15
    "    path('jobs/', TemplateView.as_view(template_name='jobs.html')),\n"  # 16
    "    path('local/', local_view),\n"  # 17
    "    path('api/', include('shop.api.urls')),\n"  # 18
    "]\n"
)
_ROUTES = {"/billing/": 13, "/report/": 14, "/export/": 15, "/jobs/": 16, "/local/": 17, "/api/": 18}


def _repo(root: Path) -> ScanResult:
    (root / "shop").mkdir(parents=True)
    (root / "shop" / "__init__.py").write_text("", encoding="utf-8")
    (root / "shop" / "billing.py").write_text(_BILLING, encoding="utf-8")
    (root / "shop" / "views.py").write_text(_VIEWS, encoding="utf-8")
    (root / "shop" / "urls.py").write_text(_URLS, encoding="utf-8")
    routes = [Route(path=p, method="GET", file="shop/urls.py", line=ln) for p, ln in _ROUTES.items()]
    return ScanResult(root=str(root), routes=routes)


def _sinks_by_route(root: Path) -> dict[str, set[tuple[str, int]]]:
    out: dict[str, set[tuple[str, int]]] = {p: set() for p in _ROUTES}
    for chain in analyze_taint(_repo(root), root):
        out[chain.route_path].add((chain.sink_file, chain.sink_line))
    return out


def test_each_route_reaches_only_its_own_views_sinks(tmp_path: Path) -> None:
    got = _sinks_by_route(tmp_path)
    assert got["/report/"] == {("shop/views.py", 6)}
    assert got["/export/"] == {("shop/views.py", 12)}
    assert got["/billing/"] == set()  # its view has no sink; views.py isn't its module
    assert got["/jobs/"] == set()  # a Django generic view runs no repo code


def test_unknown_handlers_fall_back_to_the_urlconf_walk(tmp_path: Path) -> None:
    got = _sinks_by_route(tmp_path)
    # A view defined in urls.py, and an include(), keep the old reach:
    # everything urls.py imports, which includes both views.py sinks.
    assert got["/local/"] == {("shop/views.py", 6), ("shop/views.py", 12)}
    assert got["/api/"] == got["/local/"]


def test_seeds_name_the_view_module_and_definition(tmp_path: Path) -> None:
    scan = _repo(tmp_path)
    files = {
        str(p.relative_to(tmp_path)): p for p in tmp_path.rglob("*.py")
    }
    cache: dict = {}
    seeds = {r.path: _py_urlconf_seeds(r, _URLS, "shop/urls.py", files, cache) for r in scan.routes}
    assert seeds["/billing/"] == [("shop/billing.py", "billing_page")]
    assert seeds["/report/"] == [("shop/views.py", "report")]
    assert seeds["/export/"] == [("shop/views.py", "Export")]
    assert seeds["/jobs/"] == []
    assert seeds["/local/"] is None and seeds["/api/"] is None
    assert _py_def_span(_VIEWS, "Export") == (10, 13)
    # A module imported relatively and referenced by attribute.
    relative = "from . import views\nurlpatterns = [path('r/', views.report)]\n"
    route = Route(path="/r/", method="GET", file="shop/urls.py", line=2)
    assert _py_urlconf_seeds(route, relative, "shop/urls.py", files, {}) == [("shop/views.py", "report")]


def test_urlconf_helpers_never_raise_on_garbage() -> None:
    rng = random.Random(372)
    alphabet = "from import as .(),\n path re_path url include views x_1 'b' \"c\" \\ #"
    files = {"a/views.py": Path("a/views.py"), "a/__init__.py": Path("a/__init__.py")}
    for _ in range(2000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 160)))
        _py_bindings(text, "a/urls.py", files)
        _py_def_span(text, "x_1")
        route = Route(path="/x", method="GET", file="a/urls.py", line=rng.randint(1, 6))
        _py_urlconf_seeds(route, text, "a/urls.py", files, {})
