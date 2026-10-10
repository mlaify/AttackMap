from attackmap.handler_span import MAX_SPAN, span_bounds, span_text

SRC = """\
@login_required
@app.get("/a/<id>")
def a(id):
    return A.get(id)

@app.get("/b/<id>")
def b(id):
    return B.get(id).owned_by(current_user)
""".splitlines()


def test_span_stops_at_next_route_and_includes_decorators():
    start, end = span_bounds(2, SRC, [2, 6])
    assert SRC[start:end] == SRC[0:5]


def test_sibling_guard_does_not_leak():
    assert "owned_by" not in span_text(2, SRC, [2, 6])
    assert "owned_by" in span_text(6, SRC, [2, 6])


def test_unsorted_route_lines_and_lineless_route():
    assert span_bounds(2, SRC, [6, 2]) == span_bounds(2, SRC, [2, 6])
    assert span_text(None, SRC, [2, 6]) == "\n".join(SRC)


def test_span_is_capped():
    lines = ["@app.get('/x')"] + ["pass"] * (MAX_SPAN * 3)
    start, end = span_bounds(1, lines, [1])
    assert end - start <= MAX_SPAN


def test_next_routes_decorators_are_not_ours():
    lines = [
        "@app.get('/a/<id>')",
        "def a(id):",
        "    return A.get(id)",
        "@roles_required('admin')",
        "@app.get('/b/<id>')",
        "def b(id):",
        "    return B.get(id)",
    ]
    assert "roles_required" not in span_text(1, lines, [1, 5])
    assert "roles_required" in span_text(5, lines, [1, 5])


def test_max_span_widens_the_cap():
    lines = ["@app.get('/x')"] + ["pass"] * (MAX_SPAN * 3)
    start, end = span_bounds(1, lines, [1], max_span=MAX_SPAN * 2)
    assert end - start == MAX_SPAN * 2
