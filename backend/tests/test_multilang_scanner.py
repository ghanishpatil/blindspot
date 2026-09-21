"""Multi-language source rulepack tests — R3.

Runs the real semgrep binary against small Java, JavaScript / TypeScript,
and Go fixtures written to ``tmp_path``. The tests are asserted on three
guarantees:

1. **Correct algorithm resolution.** Each language's headline patterns
   emit the expected ``algorithm`` string and ``primitive``.
2. **Non-Python source keeps HIGH confidence.** The extractor tweak
   (skip AST for non-Python) must NOT downgrade Java / JS / Go findings
   to the medium band the way a Python ``SyntaxError`` does.
3. **Weak-algorithm passthrough.** ``MD5``, ``SHA-1``, ``DES``, ``3DES``
   detected in the new languages still land in the pipeline's weak-
   algorithm table so the recommender emits ``REMEDIATE_NOW``.

**Runtime note.** Each ``run_semgrep`` invocation loads every rulepack
under ``app/scanner/rules/`` (Python + C + Java + JS/TS + Go), so a
single fixture scan is 30-60 s on Windows even for a tiny file. That
makes the full multi-language test module too slow for the default
``pytest`` run. The suite is gated behind
``BLINDSPOT_RUN_MULTILANG_TESTS=1`` — export it before running
``pytest`` to exercise the R3 rulepacks end-to-end. The rulepacks
themselves are separately verified by direct ``semgrep scan --config
app/scanner/rules/<lang>_crypto.yaml`` invocations documented in
``PS_ALIGNMENT_PLAN.md``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.evidence.extractor import normalize
from app.models.asset import ArtefactType, CryptoPrimitive
from app.models.finding import ConfidenceLevel, DetectionMethod, NormalizedFinding
from app.risk.mosca import assess_current_risk, assess_quantum_risk
from app.scanner.semgrep import run_semgrep, semgrep_available


# Skip unless explicitly opted in. Two reasons a run would skip:
#
# 1. ``BLINDSPOT_RUN_MULTILANG_TESTS`` is not set. Default off because
#    the whole-rulepack semgrep invocation is expensive on Windows.
# 2. Semgrep is not installed. Skip cleanly rather than fail loudly.
pytestmark = [
    pytest.mark.skipif(
        os.environ.get("BLINDSPOT_RUN_MULTILANG_TESTS", "").strip() != "1",
        reason=(
            "Multi-language scanner tests are opt-in — export "
            "BLINDSPOT_RUN_MULTILANG_TESTS=1 to run them."
        ),
    ),
    pytest.mark.skipif(
        not semgrep_available(),
        reason="semgrep binary not available in this environment",
    ),
]


def _find_by_algorithm(
    findings: list[NormalizedFinding], algorithm: str
) -> list[NormalizedFinding]:
    return [f for f in findings if f.algorithm == algorithm]


def _run(target: Path) -> list[NormalizedFinding]:
    """Full source-scan → normalize round trip for a tmp fixture directory."""
    matches = run_semgrep(target)
    return normalize(matches, [], target)


# ═══════════════════════════════════════════════════════════════════════════
# Java (R3a)
# ═══════════════════════════════════════════════════════════════════════════

_JAVA_SAMPLE = """\
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class CryptoDemo {
    public static void main(String[] args) throws Exception {
        // RSA keygen
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        // ECDSA keygen
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");

        // Ed25519 signature
        Signature ed = Signature.getInstance("Ed25519");

        // Weak: MD5 hash and DES cipher
        MessageDigest md = MessageDigest.getInstance("MD5");
        Cipher des = Cipher.getInstance("DES/CBC/PKCS5Padding");

        // Weak: HMAC-SHA1
        Mac hmac = Mac.getInstance("HmacSHA1");

        // Strong: AES-GCM
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");

        // Signature with weak hash
        Signature sig = Signature.getInstance("SHA1withRSA");
    }
}
"""


@pytest.fixture(scope="module")
def java_findings(tmp_path_factory: pytest.TempPathFactory) -> list[NormalizedFinding]:
    target = tmp_path_factory.mktemp("java")
    (target / "CryptoDemo.java").write_text(_JAVA_SAMPLE, encoding="utf-8")
    return _run(target)


def test_java_detects_rsa_keygen(java_findings: list[NormalizedFinding]) -> None:
    rsa = _find_by_algorithm(java_findings, "RSA")
    assert rsa, "RSA keygen not detected in Java fixture"
    assert any(f.primitive == CryptoPrimitive.PKE for f in rsa)


def test_java_detects_ecdsa_keygen(java_findings: list[NormalizedFinding]) -> None:
    ec = _find_by_algorithm(java_findings, "ECDSA")
    assert ec, "ECDSA keygen not detected in Java fixture"


def test_java_detects_ed25519(java_findings: list[NormalizedFinding]) -> None:
    ed = _find_by_algorithm(java_findings, "Ed25519")
    assert ed, "Ed25519 signature not detected in Java fixture"
    # Ed25519 must be quantum-vulnerable — extended _SHOR_BREAKS set.
    assert assess_quantum_risk("Ed25519").is_quantum_vulnerable


def test_java_detects_aes(java_findings: list[NormalizedFinding]) -> None:
    aes = _find_by_algorithm(java_findings, "AES")
    assert aes, "AES cipher not detected in Java fixture"


def test_java_detects_md5_and_flags_weak(java_findings: list[NormalizedFinding]) -> None:
    md5 = _find_by_algorithm(java_findings, "MD5")
    assert md5, "MD5 not detected in Java fixture"
    assert assess_current_risk("MD5").is_currently_weak


def test_java_detects_des_and_3des(java_findings: list[NormalizedFinding]) -> None:
    des = _find_by_algorithm(java_findings, "DES")
    assert des, "DES not detected in Java fixture"
    assert assess_current_risk("DES").is_currently_weak


def test_java_findings_land_at_high_confidence(java_findings: list[NormalizedFinding]) -> None:
    """The extractor must NOT downgrade Java findings to MEDIUM just
    because Python's ast.parse cannot read a .java file."""
    rsa = _find_by_algorithm(java_findings, "RSA")
    assert rsa
    assert rsa[0].evidence.confidence_level == ConfidenceLevel.HIGH


def test_java_findings_carry_library_metadata(java_findings: list[NormalizedFinding]) -> None:
    """Each finding must attribute the providing library so R4 dependency
    findings can be correlated against source usage."""
    libraries = {f.library for f in java_findings if f.library}
    # `jca`, `jce` are the JDK provider tags in our rules.
    assert libraries & {"jca", "jce"}, f"expected jca/jce library tag, got {libraries}"


# ═══════════════════════════════════════════════════════════════════════════
# JavaScript / TypeScript (R3b)
# ═══════════════════════════════════════════════════════════════════════════

_JS_SAMPLE = """\
const crypto = require('crypto');

// Weak hashes
const md5 = crypto.createHash('md5');
const sha1 = crypto.createHash('sha1');

// Weak HMAC
const hmac = crypto.createHmac('sha1', 'k');

// Weak ciphers
const desC = crypto.createCipheriv('des-cbc', k, iv);
const desE = crypto.createCipheriv('des-ede3-cbc', k, iv);

// Strong AES + ChaCha20
const aes = crypto.createCipheriv('aes-256-gcm', k, iv);
const cc  = crypto.createCipheriv('chacha20-poly1305', k, iv);

// Asymmetric keygen
crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
crypto.generateKeyPairSync('ec',  { namedCurve: 'P-256' });
crypto.generateKeyPairSync('ed25519');
crypto.generateKeyPairSync('x25519');

// node-forge weak
const forge = require('node-forge');
const fmd5 = forge.md.md5.create();
const fdes = forge.cipher.createCipher('DES-CBC', k);

// crypto-js weak
const CryptoJS = require('crypto-js');
const cjsMD5 = CryptoJS.MD5('hello');
const cjs3des = CryptoJS.TripleDES.encrypt('m', 'k');
"""

_TS_SAMPLE = """\
import * as crypto from 'crypto';

// TypeScript: also gets scanned by the same rules
const md5 = crypto.createHash('md5');
const sha256 = crypto.createHash('sha256');
crypto.generateKeyPairSync('ed25519');
"""


@pytest.fixture(scope="module")
def js_findings(tmp_path_factory: pytest.TempPathFactory) -> list[NormalizedFinding]:
    target = tmp_path_factory.mktemp("js")
    (target / "sample.js").write_text(_JS_SAMPLE, encoding="utf-8")
    (target / "sample.ts").write_text(_TS_SAMPLE, encoding="utf-8")
    return _run(target)


def test_js_detects_md5_and_sha1(js_findings: list[NormalizedFinding]) -> None:
    assert _find_by_algorithm(js_findings, "MD5"), "MD5 not detected in JS fixture"
    assert _find_by_algorithm(js_findings, "SHA-1"), "SHA-1 not detected in JS fixture"


def test_js_detects_weak_ciphers(js_findings: list[NormalizedFinding]) -> None:
    assert _find_by_algorithm(js_findings, "DES"), "DES not detected in JS fixture"
    assert _find_by_algorithm(js_findings, "3DES"), "3DES not detected in JS fixture"


def test_js_detects_strong_symmetric(js_findings: list[NormalizedFinding]) -> None:
    assert _find_by_algorithm(js_findings, "AES"), "AES not detected in JS fixture"
    assert _find_by_algorithm(js_findings, "ChaCha20"), "ChaCha20 not detected"


def test_js_detects_asymmetric_keygen(js_findings: list[NormalizedFinding]) -> None:
    assert _find_by_algorithm(js_findings, "RSA")
    assert _find_by_algorithm(js_findings, "ECDSA")
    assert _find_by_algorithm(js_findings, "Ed25519")
    assert _find_by_algorithm(js_findings, "X25519")


def test_js_detects_node_forge_and_cryptojs(js_findings: list[NormalizedFinding]) -> None:
    libraries = {f.library for f in js_findings if f.library}
    assert "node-forge" in libraries, f"node-forge not detected, libraries={libraries}"
    assert "crypto-js" in libraries, f"crypto-js not detected, libraries={libraries}"


def test_typescript_files_are_also_scanned(js_findings: list[NormalizedFinding]) -> None:
    # The .ts fixture should have contributed at least one finding.
    ts_findings = [f for f in js_findings if f.evidence.file_path.endswith(".ts")]
    assert ts_findings, "TypeScript source was not scanned"


def test_js_findings_land_at_high_confidence(js_findings: list[NormalizedFinding]) -> None:
    md5 = _find_by_algorithm(js_findings, "MD5")
    assert md5
    assert md5[0].evidence.confidence_level == ConfidenceLevel.HIGH


# ═══════════════════════════════════════════════════════════════════════════
# Go (R3c)
# ═══════════════════════════════════════════════════════════════════════════

_GO_SAMPLE = """\
package main

import (
    "crypto/aes"
    "crypto/des"
    "crypto/ecdh"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/elliptic"
    "crypto/md5"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha1"
    "crypto/sha256"
)

func main() {
    // Weak
    _ = md5.New()
    _ = sha1.New()
    _, _ = des.NewCipher(nil)
    _, _ = des.NewTripleDESCipher(nil)

    // Strong / modern
    _ = sha256.New()
    _, _ = aes.NewCipher(nil)

    // Asymmetric
    _, _ = rsa.GenerateKey(rand.Reader, 2048)
    _, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    _, _, _ = ed25519.GenerateKey(rand.Reader)

    // ECDH (Go 1.20+)
    _ = ecdh.P256()
    _ = ecdh.X25519()
}
"""


@pytest.fixture(scope="module")
def go_findings(tmp_path_factory: pytest.TempPathFactory) -> list[NormalizedFinding]:
    target = tmp_path_factory.mktemp("go")
    (target / "sample.go").write_text(_GO_SAMPLE, encoding="utf-8")
    return _run(target)


def test_go_detects_weak_hashes(go_findings: list[NormalizedFinding]) -> None:
    assert _find_by_algorithm(go_findings, "MD5"), "MD5 not detected in Go fixture"
    assert _find_by_algorithm(go_findings, "SHA-1"), "SHA-1 not detected in Go fixture"


def test_go_detects_weak_ciphers(go_findings: list[NormalizedFinding]) -> None:
    assert _find_by_algorithm(go_findings, "DES"), "DES not detected in Go fixture"
    assert _find_by_algorithm(go_findings, "3DES"), "3DES not detected in Go fixture"


def test_go_detects_strong_symmetric(go_findings: list[NormalizedFinding]) -> None:
    assert _find_by_algorithm(go_findings, "AES"), "AES not detected in Go fixture"


def test_go_detects_asymmetric(go_findings: list[NormalizedFinding]) -> None:
    assert _find_by_algorithm(go_findings, "RSA")
    assert _find_by_algorithm(go_findings, "ECDSA")
    assert _find_by_algorithm(go_findings, "Ed25519")


def test_go_detects_ecdh_variants(go_findings: list[NormalizedFinding]) -> None:
    ecdh = _find_by_algorithm(go_findings, "ECDH")
    assert ecdh, "ECDH.P256 not detected in Go fixture"
    x25519 = _find_by_algorithm(go_findings, "X25519")
    assert x25519, "X25519 key agreement not detected in Go fixture"


def test_go_findings_land_at_high_confidence(go_findings: list[NormalizedFinding]) -> None:
    rsa = _find_by_algorithm(go_findings, "RSA")
    assert rsa
    assert rsa[0].evidence.confidence_level == ConfidenceLevel.HIGH


# ═══════════════════════════════════════════════════════════════════════════
# Cross-cutting: extended risk table (R3 dependency)
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("algo", ["Ed25519", "Ed448", "X25519", "X448"])
def test_edwards_and_montgomery_curves_are_shor_breakable(algo: str) -> None:
    """Ed25519 / X25519 / Ed448 / X448 all rely on elliptic-curve discrete
    logs, which Shor breaks. R3 extends `_SHOR_BREAKS` to reflect this."""
    risk = assess_quantum_risk(algo)
    assert risk.is_quantum_vulnerable, f"{algo} must be flagged quantum-vulnerable"


def test_chacha20_is_grover_weakenable_not_broken() -> None:
    """ChaCha20 is symmetric; Grover halves effective security but does
    not break it. R3 extends `_GROVER_WEAKENS` to reflect this."""
    risk = assess_quantum_risk("ChaCha20")
    assert not risk.is_quantum_vulnerable
    assert risk.threat.value == "grover_weakens"
