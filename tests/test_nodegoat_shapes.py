"""OWASP NodeGoat shapes (real-world benchmark): constructor-function handlers, DAO access, `isLoggedIn`,
sinks named in comments, and `needle` as an HTTP client."""

from pathlib import Path

from attackmap.authz import analyze_authz
from attackmap.scanner import scan_repo
from attackmap.threat_model import generate_findings

_FILES = {
    "server.js": "const express = require('express');\nconst app = express();\nrequire('./routes/index')(app, db);\n",
    "routes/index.js": (
        "const ContributionsHandler = require('./contributions');\n"
        "const AllocationsHandler = require('./allocations');\n"
        "const ResearchHandler = require('./research');\n"
        "module.exports = (app, db) => {\n"
        "  const isLoggedIn = sessionHandler.isLoggedInMiddleware;\n"
        "  const contributionsHandler = new ContributionsHandler(db);\n"
        "  const allocationsHandler = new AllocationsHandler(db);\n"
        "  const researchHandler = new ResearchHandler(db);\n"
        "  app.post('/contributions', isLoggedIn, contributionsHandler.handleUpdate);\n"
        "  app.get('/allocations/:userId', isLoggedIn, allocationsHandler.displayAllocations);\n"
        "  app.get('/research', isLoggedIn, researchHandler.displayResearch);\n"
        "};\n"
    ),
    "routes/contributions.js": (
        "function ContributionsHandler(db) {\n"
        "  this.handleUpdate = (req, res) => {\n"
        "    // Insecure use of eval() to parse inputs\n"
        "    const preTax = eval(req.body.preTax);\n"
        "    res.send(String(preTax));\n"
        "  };\n"
        "}\n"
        "module.exports = ContributionsHandler;\n"
    ),
    "routes/allocations.js": (
        "const AllocationsDAO = require('../data/allocations-dao').AllocationsDAO;\n"
        "function AllocationsHandler(db) {\n"
        "  const allocationsDAO = new AllocationsDAO(db);\n"
        "  this.displayAllocations = (req, res, next) => {\n"
        "    const { userId } = req.params;\n"
        "    allocationsDAO.getByUserIdAndThreshold(userId, req.query.threshold, (err, a) => res.render('allocations', a));\n"
        "  };\n"
        "}\n"
        "module.exports = AllocationsHandler;\n"
    ),
    "routes/research.js": (
        "const needle = require('needle');\n"
        "function ResearchHandler(db) {\n"
        "  this.displayResearch = (req, res) => {\n"
        "    return needle.get(req.query.url + req.query.symbol, (e, r, body) => res.end(body));\n"
        "  };\n"
        "}\n"
        "module.exports = ResearchHandler;\n"
    ),
}


def test_nodegoat_shapes(tmp_path: Path) -> None:
    for rel, text in _FILES.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
    scan = scan_repo(tmp_path)
    traced = {(c.route_path, c.sink_kind, c.sink_file, c.sink_line) for c in scan.taint_chains if c.source_kind}
    assert ("/contributions", "eval", "routes/contributions.js", 4) in traced
    assert ("/research", "ssrf", "routes/research.js", 4) in traced
    assert not [c for c in scan.taint_chains if c.sink_file == "routes/contributions.js" and c.sink_line == 3]
    assert [(c.route_method, c.route_path) for c in analyze_authz(scan, tmp_path)] == [("GET", "/allocations/:userId")]
    titles = {f.title for f in generate_findings(scan)}
    assert not [t for t in titles if "without an authentication control" in t]
