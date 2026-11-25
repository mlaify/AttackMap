"""Tests for insecure-crypto & weak-randomness detection (#70)."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.crypto import find_crypto_weaknesses
from attackmap.models import ScanResult
from attackmap.scanner import scan_repo
from attackmap.threat_model import generate_findings


def _kinds(content: str) -> set[str]:
    return {w.kind for w in find_crypto_weaknesses(content, "f.py")}


# ---------------------------------------------------------------------------
# Weak password hashing (gated on security context)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "import hashlib\nh = hashlib.md5(password.encode()).hexdigest()\n",
        "digest = hashlib.sha1(user_password)\n",
        "const h = createHash('md5').update(password).digest('hex')\n",
        'MessageDigest md = MessageDigest.getInstance("MD5");\nmd.update(secret.getBytes());\n',
        'byte[] h = MessageDigest.getInstance("SHA-1").digest(password.getBytes());\n',
    ],
)
def test_weak_password_hash_detected(content: str) -> None:
    assert "weak_password_hash" in _kinds(content)


def test_md5_without_security_context_not_flagged() -> None:
    # Hashing a file for a cache key is not a password-hash weakness.
    content = "etag = hashlib.md5(file_bytes).hexdigest()\n"
    assert "weak_password_hash" not in _kinds(content)
    content = 'MessageDigest md = MessageDigest.getInstance("MD5");\nmd.update(fileBytes);\n'
    assert "weak_password_hash" not in _kinds(content)


def test_jvm_sources_get_the_crypto_rules(tmp_path: Path) -> None:
    # Core's per-file pass doesn't read .java (the language plugin does); the
    # repo pass still applies the crypto rules there (WebGoat HashingAssignment).
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Hashing.java").write_text(
        'class Hashing {\n  String h(String secret) throws Exception {\n'
        '    MessageDigest md = MessageDigest.getInstance("MD5");\n    md.update(secret.getBytes());\n'
        '    Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");\n    return "";\n  }\n}\n',
        encoding="utf-8",
    )
    (tmp_path / "src" / "HashingTest.java").write_text('class HashingTest { Cipher c = Cipher.getInstance("RC4"); }\n')
    found = {(w.kind, w.file, w.line) for w in scan_repo(tmp_path).crypto_weaknesses}
    assert found == {("weak_password_hash", "src/Hashing.java", 3), ("weak_cipher", "src/Hashing.java", 5)}


# ---------------------------------------------------------------------------
# Weak ciphers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "from Crypto.Cipher import DES\nc = DES.new(key)\n",
        "cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))\n",
        "c = ARC4.new(key)\n",
        "Cipher rc4 = Cipher.getInstance(\"RC4\");\n",
        "b = new BlowfishEngine();\n",
    ],
)
def test_weak_cipher_detected(content: str) -> None:
    assert "weak_cipher" in _kinds(content)


def test_aes_gcm_not_flagged_as_weak_cipher() -> None:
    content = "cipher = Cipher(algorithms.AES(key), modes.GCM(iv))\n"
    assert "weak_cipher" not in _kinds(content)


# ---------------------------------------------------------------------------
# ECB mode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "cipher = AES.new(key, AES.MODE_ECB)\n",
        'c = Cipher.getInstance("AES/ECB/PKCS5Padding");\n',
        'Cipher c = Cipher.getInstance("AES");\n',  # Java default = ECB
    ],
)
def test_ecb_mode_detected(content: str) -> None:
    assert "ecb_mode" in _kinds(content)


def test_gcm_mode_not_flagged() -> None:
    content = "cipher = AES.new(key, AES.MODE_GCM)\n"
    assert "ecb_mode" not in _kinds(content)


# ---------------------------------------------------------------------------
# Static IV / salt
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        'iv = b"1234567890123456"\n',
        "salt = 'staticsalt123'\n",
        'IV: "abcdef012345"\n',
    ],
)
def test_static_iv_salt_detected(content: str) -> None:
    assert "static_iv_salt" in _kinds(content)


def test_hardcoded_nonce_not_flagged_as_iv_salt() -> None:
    # Hardcoded nonces are mostly HTTP-auth/protocol test data, not IV misuse.
    assert "static_iv_salt" not in _kinds('nonce = "abc123def456"\n')


def test_random_iv_not_flagged() -> None:
    content = "iv = os.urandom(16)\n"
    assert "static_iv_salt" not in _kinds(content)


# ---------------------------------------------------------------------------
# Insecure randomness (gated on security context)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "token = str(random.randint(1000, 9999))\n",
        "const sessionId = Math.random().toString(36)\n",
        "$otp = mt_rand(100000, 999999);\n",
        "reset_token = random.choice(alphabet)\n",
    ],
)
def test_insecure_random_detected(content: str) -> None:
    assert "insecure_random" in _kinds(content)


def test_non_security_random_not_flagged() -> None:
    # Jitter/backoff randomness is fine — no security-context identifier.
    content = "jitter = random.random() * backoff\nx = Math.random()\n"
    assert "insecure_random" not in _kinds(content)


# ---------------------------------------------------------------------------
# Insecure TLS
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "r = requests.get(url, verify=False)\n",
        "const agent = new https.Agent({ rejectUnauthorized: false })\n",
        "tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}\n",
        "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n",
    ],
)
def test_insecure_tls_detected(content: str) -> None:
    assert "insecure_tls" in _kinds(content)


def test_verify_true_not_flagged() -> None:
    content = "r = requests.get(url, verify=True)\n"
    assert "insecure_tls" not in _kinds(content)


# ---------------------------------------------------------------------------
# Dedup + metadata
# ---------------------------------------------------------------------------


def test_same_line_not_double_reported() -> None:
    # DES appears twice on one line; one weakness per (kind, line).
    content = "algo = DES if legacy else DES\n"
    weaknesses = [w for w in find_crypto_weaknesses(content, "f.py") if w.kind == "weak_cipher"]
    assert len(weaknesses) == 1
    assert weaknesses[0].line == 1


def test_weakness_carries_evidence_and_severity() -> None:
    content = "h = hashlib.md5(password)\n"
    w = find_crypto_weaknesses(content, "auth.py")[0]
    assert w.file == "auth.py"
    assert w.line == 1
    assert "md5" in (w.evidence_text or "").lower()
    assert w.severity == "high"


# ---------------------------------------------------------------------------
# Findings via threat_model
# ---------------------------------------------------------------------------


def test_weak_hash_finding_high_with_technique() -> None:
    from attackmap.models import CryptoWeakness

    scan = ScanResult(
        root="/",
        crypto_weaknesses=[CryptoWeakness(kind="weak_password_hash", file="a.py", line=3, severity="high")],
    )
    findings = [f for f in generate_findings(scan) if "insecure-crypto" in f.tags]
    assert findings
    assert findings[0].severity == "high"
    assert findings[0].attack_techniques[0].technique_id == "T1110.002"


def test_insecure_tls_finding_maps_to_aitm() -> None:
    from attackmap.models import CryptoWeakness

    scan = ScanResult(
        root="/",
        crypto_weaknesses=[CryptoWeakness(kind="insecure_tls", file="net.go", line=8, severity="high")],
    )
    finding = next(f for f in generate_findings(scan) if "insecure-crypto" in f.tags)
    assert finding.attack_techniques[0].technique_id == "T1557"


def test_distinct_kinds_yield_distinct_findings() -> None:
    from attackmap.models import CryptoWeakness

    scan = ScanResult(
        root="/",
        crypto_weaknesses=[
            CryptoWeakness(kind="ecb_mode", file="a.py", line=1, severity="medium"),
            CryptoWeakness(kind="weak_cipher", file="b.py", line=2, severity="high"),
        ],
    )
    titles = {f.title for f in generate_findings(scan) if "insecure-crypto" in f.tags}
    assert any("ECB" in t for t in titles)
    assert any("cipher" in t for t in titles)


# ---------------------------------------------------------------------------
# End-to-end via scan_repo
# ---------------------------------------------------------------------------


def test_scan_repo_populates_crypto_weaknesses(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "import hashlib\n"
        "def check(password):\n"
        "    return hashlib.md5(password.encode()).hexdigest()\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert any(w.kind == "weak_password_hash" for w in scan.crypto_weaknesses)
    findings = [f for f in generate_findings(scan) if "insecure-crypto" in f.tags]
    assert findings


def test_scan_repo_clean_file_no_crypto_findings(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text(
        "import secrets, hashlib\n"
        "token = secrets.token_hex(16)\n"
        "etag = hashlib.sha256(file_bytes).hexdigest()\n",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert scan.crypto_weaknesses == []


def _kinds(content: str, f: str = "x.go"):
    from attackmap.crypto import find_crypto_weaknesses
    return {w.kind for w in find_crypto_weaknesses(content, f)}


def test_go_weak_hash_over_password() -> None:
    assert "weak_password_hash" in _kinds("h := md5.Sum([]byte(password))\n")
    # non-security md5 (checksum) is not flagged
    assert "weak_password_hash" not in _kinds("sum := md5.Sum(fileBytes)\n")


def test_go_weak_cipher_and_rng() -> None:
    assert "weak_cipher" in _kinds("block, _ := des.NewCipher(key)\n")
    assert "weak_cipher" in _kinds('import "crypto/rc4"\n')
    assert "insecure_random" in _kinds("token := fmt.Sprint(rand.Intn(1000000))\n")
    # secure crypto/rand-style rand.Int is NOT flagged (ambiguous func excluded)
    assert "insecure_random" not in _kinds("n, _ := rand.Int(rand.Reader, max) // token\n")


def test_php_mcrypt_and_tls() -> None:
    assert "weak_cipher" in _kinds("$c = mcrypt_encrypt(MCRYPT_DES, $key, $data);\n", "x.php")
    assert "insecure_tls" in _kinds("curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);\n", "x.php")
    assert "insecure_tls" in _kinds("$opts = ['verify' => false];\n", "x.php")


def test_php_weak_hash_over_password() -> None:
    assert "weak_password_hash" in _kinds("$h = md5($password);\n", "x.php")


def test_crypto_matches_code_not_comments_prints_or_prose() -> None:
    # #457: DVWA's cryptography module.
    from attackmap.crypto import find_crypto_weaknesses

    php = (
        "<?php\n"
        'define ("IV", "1234567812345678");\n'
        '# print "IV: " . byte_array_to_string ($iv) . "\\n";\n'
        'print "IV: " . (IV) . "\\n";\n'
        '$fields = array("iv:",     // Required value\n    "key:");\n'
        '$e = openssl_encrypt($p, \'aes-128-ecb\', $key, OPENSSL_PKCS1_PADDING);\n'
        "echo \"<li>Implementing and breaking AES ECB</li>\";\n"
        "// cipher = AES.new(key, AES.MODE_ECB)\n"
    )
    assert [(w.kind, w.line) for w in find_crypto_weaknesses(php, "c.php")] == [("ecb_mode", 7), ("static_iv_salt", 2)]
    py = "from cryptography.hazmat.primitives.ciphers import modes\nc = Cipher(algorithms.AES(k), modes.ECB())\n"
    assert [(w.kind, w.line) for w in find_crypto_weaknesses(py, "c.py")] == [("ecb_mode", 2)]


def test_weak_hash_helper_called_with_a_password_is_flagged_at_its_definition(tmp_path) -> None:
    # #446: Juice Shop's `security.hash(clearTextPassword)` wraps MD5 in lib/insecurity.ts.
    from attackmap.scanner import scan_repo

    (tmp_path / "lib").mkdir()
    (tmp_path / "models").mkdir()
    (tmp_path / "lib" / "insecurity.ts").write_text(
        "import crypto from 'node:crypto'\n"
        "export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')\n"
        "export const etag = (body: string) => crypto.createHash('md5').update(body).digest('hex')\n"
    )
    (tmp_path / "util.py").write_text("import hashlib\n\ndef digest(s):\n    return hashlib.md5(s.encode()).hexdigest()\n")
    (tmp_path / "models" / "user.ts").write_text(
        "import * as security from '../lib/insecurity'\n"
        "this.setDataValue('password', security.hash(clearTextPassword))\n"
        "const e = security.etag(responseBody)\n"
    )
    (tmp_path / "cache.py").write_text("from util import digest\nkey = digest(url)\n")
    got = [(w.kind, w.file, w.line) for w in scan_repo(tmp_path).crypto_weaknesses]
    assert got == [("weak_password_hash", "lib/insecurity.ts", 2)]


def test_plaintext_password_written_with_a_driver_insert() -> None:
    # NodeGoat user-dao.js: the bcrypt fix is commented out; `compareSync` isn't hashing.
    dao = (
        "const bcrypt = require('bcrypt-nodejs');\n"
        "this.addUser = (userName, password, callback) => {\n"
        "    const user = {\n        userName,\n        password // from the request\n"
        "        // password: bcrypt.hashSync(password, bcrypt.genSaltSync())\n    };\n"
        "    usersCol.insert(user, callback);\n};\n"
        "this.login = (password, user) => bcrypt.compareSync(password, user.password);\n"
        "this.find = (userName, password) => usersCol.findOne({ userName, password });\n"
        "this.add2 = (pwd) => db.users.insertOne({ name: 'x', password: pwd });\n"
        "this.add3 = (hashedPassword) => db.users.insertOne({ password: hashedPassword });\n"
    )
    hits = [(w.kind, w.line) for w in find_crypto_weaknesses(dao, "app/data/user-dao.js")]
    assert hits == [("plaintext_password", 5), ("plaintext_password", 12)]
    hashed = dao.replace("        password // from", "        password: bcrypt.hashSync(password), // from")
    assert find_crypto_weaknesses(hashed, "app/data/user-dao.js") == []
    assert find_crypto_weaknesses(dao, "app/user_dao.py") == []
