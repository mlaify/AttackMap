"""Per-detector taxonomy registry (#250): CWE, OWASP, ASVS and ATT&CK ids
keyed by stable rule id (#223).

Taxonomy is looked up by ``Finding.rule_id``. It is never inferred from a
finding's title or evidence text. Every id in ``threat_model.rule_catalog()``
must be registered here with at least one CWE and one OWASP category;
``tests/test_taxonomy.py`` fails when a rule is missing, so a new detector
cannot ship without a mapping.

Registering a new rule
----------------------
Add one line to ``RULE_TAXONOMY``::

    "my-new-rule": RuleTaxonomy(cwe=(918,), owasp=("A10:2021", "API7:2023"),
                                asvs=("V12.6.1",), attack=("T1190",)),

- ``cwe``: CWE ids as ints, most specific first. The first one is the
  primary CWE: it becomes the SARIF ``helpUri``. Add any new id and its
  official name to ``CWE_NAMES``.
- ``owasp``: OWASP Top 10 2021 (``A01:2021``…``A10:2021``), API Security
  Top 10 2023 (``API1:2023``…``API10:2023``) or LLM Top 10 2025 ids, as
  listed in ``OWASP_CATEGORIES``.
- ``asvs``: optional ASVS 4.0.3 requirement ids (``V5.3.4``).
- ``attack``: optional ATT&CK Enterprise technique or sub-technique ids.
  Add new ones to ``ATTACK_TECHNIQUES`` with their name and tactic. When
  set, these replace whatever ``attack_techniques`` the detector passed.

``speculative-<rule>`` (recall mode) ids inherit their base rule's entry.
Rules that flag no weakness at all go in ``INFORMATIONAL_RULES`` instead.

Verify ids against the source, not memory: cwe.mitre.org (CWE view 1000),
owasp.org/Top10, owasp.org/API-Security, the ASVS 4.0.3 JSON release and
the MITRE ATT&CK STIX bundle. The names below were checked against CWE
4.x view 1000, OWASP Top 10:2021, OWASP API Top 10:2023, OWASP LLM Top
10:2025, ASVS 4.0.3 and Enterprise ATT&CK 19.2.

This module has no package-internal imports, so ``models`` can use it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class RuleTaxonomy:
    cwe: tuple[int, ...]
    owasp: tuple[str, ...]
    asvs: tuple[str, ...] = ()
    attack: tuple[str, ...] = ()

    @property
    def cwe_ids(self) -> list[str]:
        return [f"CWE-{n}" for n in self.cwe]


# CWE names (CWE view 1000, "Research Concepts").
CWE_NAMES: dict[int, str] = {
    15: "External Control of System or Configuration Setting",
    20: "Improper Input Validation",
    22: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    78: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    94: "Improper Control of Generation of Code ('Code Injection')",
    95: "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
    200: "Exposure of Sensitive Information to an Unauthorized Actor",
    214: "Invocation of Process Using Visible Sensitive Information",
    215: "Insertion of Sensitive Information Into Debugging Code",
    250: "Execution with Unnecessary Privileges",
    284: "Improper Access Control",
    285: "Improper Authorization",
    287: "Improper Authentication",
    295: "Improper Certificate Validation",
    306: "Missing Authentication for Critical Function",
    307: "Improper Restriction of Excessive Authentication Attempts",
    319: "Cleartext Transmission of Sensitive Information",
    327: "Use of a Broken or Risky Cryptographic Algorithm",
    328: "Use of Weak Hash",
    338: "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
    345: "Insufficient Verification of Data Authenticity",
    346: "Origin Validation Error",
    347: "Improper Verification of Cryptographic Signature",
    349: "Acceptance of Extraneous Untrusted Data With Trusted Data",
    352: "Cross-Site Request Forgery (CSRF)",
    353: "Missing Support for Integrity Check",
    427: "Uncontrolled Search Path Element",
    434: "Unrestricted Upload of File with Dangerous Type",
    489: "Active Debug Code",
    494: "Download of Code Without Integrity Check",
    501: "Trust Boundary Violation",
    502: "Deserialization of Untrusted Data",
    522: "Insufficiently Protected Credentials",
    526: "Cleartext Storage of Sensitive Information in an Environment Variable",
    532: "Insertion of Sensitive Information into Log File",
    601: "URL Redirection to Untrusted Site ('Open Redirect')",
    611: "Improper Restriction of XML External Entity Reference",
    614: "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    639: "Authorization Bypass Through User-Controlled Key",
    693: "Protection Mechanism Failure",
    749: "Exposed Dangerous Method or Function",
    760: "Use of a One-Way Hash with a Predictable Salt",
    770: "Allocation of Resources Without Limits or Throttling",
    798: "Use of Hard-coded Credentials",
    829: "Inclusion of Functionality from Untrusted Control Sphere",
    862: "Missing Authorization",
    915: "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    916: "Use of Password Hash With Insufficient Computational Effort",
    918: "Server-Side Request Forgery (SSRF)",
    942: "Permissive Cross-domain Security Policy with Untrusted Domains",
    943: "Improper Neutralization of Special Elements in Data Query Logic",
    1004: "Sensitive Cookie Without 'HttpOnly' Flag",
    1204: "Generation of Weak Initialization Vector (IV)",
    1321: "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')",
    1333: "Inefficient Regular Expression Complexity",
    1336: "Improper Neutralization of Special Elements Used in a Template Engine",
    1357: "Reliance on Insufficiently Trustworthy Component",
    1395: "Dependency on Vulnerable Third-Party Component",
    1427: "Improper Neutralization of Input Used for LLM Prompting",
}

OWASP_CATEGORIES: dict[str, str] = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery (SSRF)",
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
    "LLM01:2025": "Prompt Injection",
}

# ATT&CK Enterprise techniques: id -> (name, tactic(s)). Sub-technique
# names are "Parent: Sub". Tactic names follow Enterprise ATT&CK 19.
ATTACK_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1027": ("Obfuscated Files or Information", "Stealth"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "Execution"),
    "T1059.007": ("Command and Scripting Interpreter: JavaScript", "Execution"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1078": ("Valid Accounts", "Stealth / Persistence / Privilege Escalation / Initial Access"),
    "T1078.004": ("Valid Accounts: Cloud Accounts", "Stealth / Persistence / Privilege Escalation / Initial Access"),
    "T1098": ("Account Manipulation", "Persistence / Privilege Escalation"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.002": ("Brute Force: Password Cracking", "Credential Access"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1195.001": ("Supply Chain Compromise: Compromise Software Dependencies and Development Tools", "Initial Access"),
    "T1195.002": ("Supply Chain Compromise: Compromise Software Supply Chain", "Initial Access"),
    "T1199": ("Trusted Relationship", "Initial Access"),
    "T1204.001": ("User Execution: Malicious Link", "Execution"),
    "T1212": ("Exploitation for Credential Access", "Credential Access"),
    "T1485": ("Data Destruction", "Impact"),
    "T1499.003": ("Endpoint Denial of Service: Application Exhaustion Flood", "Impact"),
    "T1499.004": ("Endpoint Denial of Service: Application or System Exploitation", "Impact"),
    "T1505.003": ("Server Software Component: Web Shell", "Persistence"),
    "T1528": ("Steal Application Access Token", "Credential Access"),
    "T1539": ("Steal Web Session Cookie", "Credential Access"),
    "T1552": ("Unsecured Credentials", "Credential Access"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "Credential Access"),
    "T1552.005": ("Unsecured Credentials: Cloud Instance Metadata API", "Credential Access"),
    "T1556": ("Modify Authentication Process", "Defense Impairment / Persistence / Credential Access"),
    "T1557": ("Adversary-in-the-Middle", "Credential Access / Collection"),
    "T1565": ("Data Manipulation", "Impact"),
    "T1566.002": ("Phishing: Spearphishing Link", "Initial Access"),
    "T1574": ("Hijack Execution Flow", "Stealth / Execution"),
    "T1584.004": ("Compromise Infrastructure: Server", "Resource Development"),
    "T1600": ("Weaken Encryption", "Defense Impairment"),
    "T1606": ("Forge Web Credentials", "Credential Access"),
    "T1685": ("Disable or Modify Tools", "Defense Impairment"),
}


def attack_url(technique_id: str) -> str:
    return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"


def cwe_tag(cwe: int) -> str:
    """CodeQL-style CWE tag (``external/cwe/cwe-078``) that GitHub Code
    Scanning links to the CWE entry."""
    return f"external/cwe/cwe-{cwe:03d}"


def cwe_url(cwe: int) -> str:
    return f"https://cwe.mitre.org/data/definitions/{cwe}.html"


# Rules that report no weakness (nothing to map).
INFORMATIONAL_RULES: frozenset[str] = frozenset({"limited-surface"})

RULE_TAXONOMY: dict[str, RuleTaxonomy] = {
    # Route / surface heuristics
    "public-webhook": RuleTaxonomy(cwe=(345,), owasp=("A08:2021",), asvs=("V13.2.6",), attack=("T1190", "T1199")),
    "exposed-admin-route": RuleTaxonomy(cwe=(285,), owasp=("A01:2021", "API5:2023"), asvs=("V4.1.3",), attack=("T1078", "T1068", "T1098")),
    "upload-route": RuleTaxonomy(cwe=(434,), owasp=("A04:2021",), asvs=("V12.2.1", "V12.5.2"), attack=("T1190", "T1505.003")),
    "weak-auth-route": RuleTaxonomy(cwe=(287, 307), owasp=("A07:2021", "API2:2023"), asvs=("V2.2.1",), attack=("T1110", "T1078")),
    "unauth-outbound-integration": RuleTaxonomy(cwe=(306,), owasp=("A07:2021", "API10:2023"), asvs=("V1.2.2",), attack=("T1190", "T1199")),
    "hardcoded-secret": RuleTaxonomy(cwe=(798,), owasp=("A07:2021",), asvs=("V2.10.4", "V6.4.1"), attack=("T1552.001",)),
    "secret-env-reference": RuleTaxonomy(cwe=(526,), owasp=("A05:2021",), asvs=("V6.4.1",), attack=("T1552",)),
    "public-data-route": RuleTaxonomy(cwe=(284, 200), owasp=("A01:2021",), asvs=("V1.4.4", "V8.3.4"), attack=("T1190",)),
    "atproto-trust-chain": RuleTaxonomy(cwe=(501,), owasp=("A04:2021", "API10:2023"), attack=("T1199", "T1190")),
    "service-trust-chain": RuleTaxonomy(cwe=(501,), owasp=("A04:2021", "API10:2023"), asvs=("V1.2.2",), attack=("T1199", "T1190")),
    "framework-sink-chain": RuleTaxonomy(cwe=(20,), owasp=("A03:2021",), asvs=("V5.1.3",), attack=("T1190",)),
    "vulnerable-dependency": RuleTaxonomy(cwe=(1395,), owasp=("A06:2021",), asvs=("V14.2.1",), attack=("T1190", "T1195.001")),
    "bola-modify": RuleTaxonomy(cwe=(639,), owasp=("A01:2021", "API1:2023"), asvs=("V4.2.1",), attack=("T1190",)),
    "bola-read": RuleTaxonomy(cwe=(639,), owasp=("A01:2021", "API1:2023"), asvs=("V4.2.1",), attack=("T1190",)),
    "unauth-state-change": RuleTaxonomy(cwe=(306,), owasp=("A07:2021", "API2:2023"), asvs=("V1.2.2", "V3.7.1"), attack=("T1190",)),
    # Taint sinks (#68); speculative-<kind> inherits these
    "subprocess-shell": RuleTaxonomy(cwe=(78,), owasp=("A03:2021",), asvs=("V5.3.8",), attack=("T1059", "T1190")),
    "eval": RuleTaxonomy(cwe=(95, 94), owasp=("A03:2021",), asvs=("V5.2.4",), attack=("T1059", "T1190")),
    "exec": RuleTaxonomy(cwe=(94,), owasp=("A03:2021",), asvs=("V5.2.4",), attack=("T1059", "T1190")),
    "unsafe-deserialization": RuleTaxonomy(cwe=(502,), owasp=("A08:2021",), asvs=("V5.5.3", "V1.5.2"), attack=("T1059", "T1190")),
    "ssti": RuleTaxonomy(cwe=(1336, 94), owasp=("A03:2021",), asvs=("V5.2.5",), attack=("T1059", "T1190")),
    "ssrf": RuleTaxonomy(cwe=(918,), owasp=("A10:2021", "API7:2023"), asvs=("V5.2.6", "V12.6.1"), attack=("T1190", "T1552.005")),
    "nosql-injection": RuleTaxonomy(cwe=(943,), owasp=("A03:2021",), asvs=("V5.3.4",), attack=("T1190",)),
    "open-redirect": RuleTaxonomy(cwe=(601,), owasp=("A01:2021",), asvs=("V5.1.5",), attack=("T1204.001", "T1566.002")),
    # Crypto (#70)
    "weak-password-hash": RuleTaxonomy(cwe=(916, 328), owasp=("A02:2021",), asvs=("V2.4.1",), attack=("T1110.002",)),
    "weak-cipher": RuleTaxonomy(cwe=(327,), owasp=("A02:2021",), asvs=("V6.2.2", "V6.2.5"), attack=("T1600",)),
    "ecb-mode": RuleTaxonomy(cwe=(327,), owasp=("A02:2021",), asvs=("V6.2.5",), attack=("T1600",)),
    "static-iv-salt": RuleTaxonomy(cwe=(1204, 760), owasp=("A02:2021",), attack=("T1600",)),
    "insecure-random": RuleTaxonomy(cwe=(338,), owasp=("A02:2021",), asvs=("V6.3.1",), attack=("T1600",)),
    "insecure-tls": RuleTaxonomy(cwe=(295,), owasp=("A07:2021", "A02:2021"), asvs=("V9.2.1",), attack=("T1557",)),
    # Web hardening (#71)
    "cors-wildcard-credentials": RuleTaxonomy(cwe=(942,), owasp=("A05:2021", "API8:2023"), asvs=("V14.5.3",), attack=("T1539",)),
    "cors-wildcard-origin": RuleTaxonomy(cwe=(942,), owasp=("A05:2021", "API8:2023"), asvs=("V14.5.3",), attack=("T1190",)),
    "cors-untrusted-origin": RuleTaxonomy(cwe=(346, 942), owasp=("A05:2021", "API8:2023"), asvs=("V14.5.3",), attack=("T1539",)),
    "csrf-unprotected-session": RuleTaxonomy(cwe=(352,), owasp=("A01:2021",), asvs=("V4.2.2", "V3.4.3", "V13.2.3"), attack=("T1190",)),
    "csrf-disabled": RuleTaxonomy(cwe=(352,), owasp=("A01:2021",), asvs=("V4.2.2", "V13.2.3"), attack=("T1190",)),
    "insecure-cookie": RuleTaxonomy(cwe=(614, 1004), owasp=("A05:2021",), asvs=("V3.4.1", "V3.4.2"), attack=("T1539",)),
    "weak-csp": RuleTaxonomy(cwe=(693,), owasp=("A05:2021",), asvs=("V14.4.3",), attack=("T1190", "T1059.007")),
    "debug-enabled": RuleTaxonomy(cwe=(489, 215), owasp=("A05:2021", "API8:2023"), asvs=("V14.3.2",), attack=("T1190",)),
    # Code weaknesses (#77)
    "prototype-pollution": RuleTaxonomy(cwe=(1321,), owasp=("A08:2021",), attack=("T1190", "T1059.007")),
    "mass-assignment": RuleTaxonomy(cwe=(915,), owasp=("A08:2021", "API3:2023"), asvs=("V5.1.2",), attack=("T1190",)),
    "jwt-weakness": RuleTaxonomy(cwe=(347,), owasp=("A02:2021", "API2:2023"), asvs=("V3.5.3",), attack=("T1190", "T1606")),
    "xxe": RuleTaxonomy(cwe=(611,), owasp=("A05:2021",), asvs=("V5.5.2",), attack=("T1190",)),
    "redos": RuleTaxonomy(cwe=(1333,), owasp=("API4:2023",), attack=("T1499.004",)),
    "insecure-upload": RuleTaxonomy(cwe=(22, 434), owasp=("A01:2021", "A04:2021"), asvs=("V12.3.1", "V12.2.1"), attack=("T1190", "T1505.003")),
    "graphql-exposure": RuleTaxonomy(cwe=(200,), owasp=("A05:2021", "API8:2023"), attack=("T1190",)),
    "graphql-no-query-limits": RuleTaxonomy(cwe=(770,), owasp=("API4:2023",), asvs=("V13.4.1",), attack=("T1499.003",)),
    "graphql-batching": RuleTaxonomy(cwe=(770, 307), owasp=("API4:2023", "API2:2023"), asvs=("V13.4.1", "V2.2.1"), attack=("T1110", "T1499.003")),
    "prompt-injection-attempt": RuleTaxonomy(cwe=(1427,), owasp=("LLM01:2025",), attack=("T1027",)),
    # CI workflows (#142)
    "script-injection": RuleTaxonomy(cwe=(78, 94), owasp=("A03:2021", "A08:2021"), attack=("T1059.004", "T1195.002")),
    "pr-target-checkout": RuleTaxonomy(cwe=(829,), owasp=("A08:2021",), asvs=("V12.3.6",), attack=("T1195.002",)),
    "unpinned-action": RuleTaxonomy(cwe=(829, 1357), owasp=("A08:2021",), asvs=("V14.2.4",), attack=("T1195.001",)),
    "secret-in-run": RuleTaxonomy(cwe=(532, 214), owasp=("A09:2021",), asvs=("V7.1.1",), attack=("T1552",)),
    "broad-permissions": RuleTaxonomy(cwe=(250,), owasp=("A01:2021",), attack=("T1078",)),
    "self-hosted-pr": RuleTaxonomy(cwe=(829,), owasp=("A08:2021",), attack=("T1195.002", "T1584.004")),
    # CI workflows, round 2 (#246)
    "workflow-run-artifact-poisoning": RuleTaxonomy(cwe=(829,), owasp=("A08:2021",), asvs=("V10.3.2", "V12.3.6"), attack=("T1195.002",)),
    "issue-comment-pr-checkout": RuleTaxonomy(cwe=(829,), owasp=("A08:2021",), asvs=("V12.3.6",), attack=("T1195.002",)),
    "github-script-injection": RuleTaxonomy(cwe=(94,), owasp=("A03:2021", "A08:2021"), asvs=("V5.2.4",), attack=("T1059.007", "T1195.002")),
    "github-env-injection": RuleTaxonomy(cwe=(94, 15), owasp=("A03:2021", "A08:2021"), attack=("T1574", "T1195.002")),
    "default-token-permissions": RuleTaxonomy(cwe=(250,), owasp=("A01:2021",), attack=("T1078",)),
    "oidc-on-untrusted-trigger": RuleTaxonomy(cwe=(250,), owasp=("A01:2021",), attack=("T1078.004",)),
    "secrets-inherit": RuleTaxonomy(cwe=(250,), owasp=("A01:2021",), attack=("T1552",)),
    "checkout-persist-credentials": RuleTaxonomy(cwe=(522,), owasp=("A04:2021",), attack=("T1552.001",)),
    "cache-poisoning-pr-target": RuleTaxonomy(cwe=(349,), owasp=("A08:2021",), attack=("T1195.002",)),
    "docker-action-unpinned": RuleTaxonomy(cwe=(829, 1357), owasp=("A08:2021",), asvs=("V14.2.4",), attack=("T1195.001",)),
    "curl-pipe-shell": RuleTaxonomy(cwe=(494,), owasp=("A08:2021",), asvs=("V10.3.2",), attack=("T1105", "T1195.002")),
    # Dependency supply-chain risk (#247).
    "dependency-confusion": RuleTaxonomy(cwe=(427, 829), owasp=("A08:2021", "A06:2021"), asvs=("V14.2.4",), attack=("T1195.001",)),
    "typosquat-candidate": RuleTaxonomy(cwe=(1357, 829), owasp=("A06:2021", "A08:2021"), asvs=("V14.2.4",), attack=("T1195.001",)),
    "mutable-vcs-dependency": RuleTaxonomy(cwe=(494, 829), owasp=("A08:2021", "A06:2021"), asvs=("V14.2.4",), attack=("T1195.001",)),
    "install-script": RuleTaxonomy(cwe=(829, 494), owasp=("A08:2021",), attack=("T1195.001", "T1059")),
    "unlocked-manifest": RuleTaxonomy(cwe=(353, 494), owasp=("A08:2021", "A06:2021"), asvs=("V14.2.4",), attack=("T1195.001",)),
    "insecure-registry": RuleTaxonomy(cwe=(319, 295, 494), owasp=("A02:2021", "A08:2021"), attack=("T1557", "T1195.001")),
    # Anomalies (#78)
    "auth-outlier": RuleTaxonomy(cwe=(862,), owasp=("A01:2021", "API5:2023"), asvs=("V4.1.3", "V13.1.4"), attack=("T1190",)),
    "validation-outlier": RuleTaxonomy(cwe=(20,), owasp=("A03:2021",), asvs=("V5.1.3",), attack=("T1190",)),
    "method-outlier": RuleTaxonomy(cwe=(749,), owasp=("A01:2021", "API5:2023"), asvs=("V13.2.1",), attack=("T1190",)),
    "invariant-violation": RuleTaxonomy(cwe=(693,), owasp=("A04:2021",), attack=("T1190",)),
}

_SPECULATIVE = "speculative-"
_ASVS_ID = re.compile(r"V\d{1,2}\.\d{1,2}\.\d{1,2}")


def taxonomy_for(rule_id: str | None) -> RuleTaxonomy | None:
    """The registered taxonomy for ``rule_id``, or ``None``. A
    ``speculative-<rule>`` id resolves to its base rule."""
    if not rule_id:
        return None
    entry = RULE_TAXONOMY.get(rule_id)
    if entry is None and rule_id.startswith(_SPECULATIVE):
        entry = RULE_TAXONOMY.get(rule_id[len(_SPECULATIVE):])
    return entry


def register(rule_id: str, entry: RuleTaxonomy) -> None:
    """Register (or replace) a rule's taxonomy at runtime, for plugins that
    emit their own rule ids. Validates the ids against the catalogs here."""
    problems = validate_entry(entry)
    if problems:
        raise ValueError(f"invalid taxonomy for {rule_id!r}: {'; '.join(problems)}")
    RULE_TAXONOMY[rule_id] = entry


def validate_entry(entry: RuleTaxonomy) -> list[str]:
    """Problems with an entry: missing CWE/OWASP, or ids unknown to the
    catalogs above (add the id and its name there first)."""
    problems: list[str] = []
    if not entry.cwe:
        problems.append("no CWE")
    if not entry.owasp:
        problems.append("no OWASP category")
    problems += [f"CWE-{c} not in CWE_NAMES" for c in entry.cwe if c not in CWE_NAMES]
    problems += [f"{o} not in OWASP_CATEGORIES" for o in entry.owasp if o not in OWASP_CATEGORIES]
    problems += [f"{t} not in ATTACK_TECHNIQUES" for t in entry.attack if t not in ATTACK_TECHNIQUES]
    problems += [f"malformed ASVS id {a}" for a in entry.asvs if not _ASVS_ID.fullmatch(a)]
    return problems


def taxonomy_label(rule_id: str | None) -> str:
    """Short inline label for Markdown, e.g. ``CWE-918 · A10:2021 · API7:2023``.
    Empty when the rule is unregistered."""
    entry = taxonomy_for(rule_id)
    if entry is None:
        return ""
    return " · ".join([*entry.cwe_ids[:2], *entry.owasp[:2]])


__all__ = [
    "ATTACK_TECHNIQUES",
    "CWE_NAMES",
    "INFORMATIONAL_RULES",
    "OWASP_CATEGORIES",
    "RULE_TAXONOMY",
    "RuleTaxonomy",
    "attack_url",
    "cwe_tag",
    "cwe_url",
    "register",
    "taxonomy_for",
    "taxonomy_label",
    "validate_entry",
]
