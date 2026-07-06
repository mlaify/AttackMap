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
        'MessageDigest md = MessageDigest.getInstance("MD5");\n',
        'MessageDigest.getInstance("SHA-1")\n',
    ],
)
def test_weak_password_hash_detected(content: str) -> None:
    assert "weak_password_hash" in _kinds(content)


def test_md5_without_security_context_not_flagged() -> None:
    # Hashing a file for a cache key is not a password-hash weakness.
    content = "etag = hashlib.md5(file_bytes).hexdigest()\n"
    assert "weak_password_hash" not in _kinds(content)


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
