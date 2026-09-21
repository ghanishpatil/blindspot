"""Evidence extraction and normalization.

Turns semgrep location data into :class:`~app.models.finding.NormalizedFinding`
objects with:

* evidence snippets sliced from the source at the byte offsets semgrep reports
* parameters extracted via Python's ``ast`` module
* confidence scores driven by detection method and parameter resolution
* the module-boundary resolution policy for Case 1 vs Case 5

Semgrep CE gives us locations but NOT metavariable bindings or matched source
text (``lines`` is ``"requires login"``).  So:

    semgrep LOCATES  →  we EXTRACT  →  ast RESOLVES
"""

from __future__ import annotations

import ast
import hashlib
import logging
from pathlib import Path
from typing import Any

from app.models.asset import (
    ArtefactType,
    CipherMode,
    CryptoPrimitive,
    CryptoUsage,
    ParameterStatus,
)
from app.models.finding import (
    DetectionMethod,
    Evidence,
    NormalizedFinding,
)

logger = logging.getLogger(__name__)


class _SkipASTAnalysis(Exception):
    """Sentinel raised to jump out of the AST-analysis block cleanly.

    Used for non-Python source files where :mod:`ast` cannot apply. Kept as a
    control-flow exception so the existing ``except SyntaxError:`` fallback
    stays untouched.
    """


# ── Algorithm metadata table ─────────────────────────────────────────────
# Keyed by the ``metadata.algorithm`` value from the semgrep rule.
# This is the ONE place where we map algorithm names to domain vocabulary.

ALGORITHM_DEFAULTS: dict[str, dict[str, Any]] = {
    "RSA": {
        "primitive": CryptoPrimitive.PKE,
        "artefact_type": ArtefactType.ENCRYPTION,
        "usage": CryptoUsage.KEY_GENERATION,
    },
    "ECDH": {
        "primitive": CryptoPrimitive.KEY_AGREE,
        "artefact_type": ArtefactType.KEY_EXCHANGE,
        "usage": CryptoUsage.KEY_ESTABLISHMENT,
    },
    "ECDSA": {
        "primitive": CryptoPrimitive.SIGNATURE,
        "artefact_type": ArtefactType.SIGNATURE,
        "usage": CryptoUsage.DIGITAL_SIGNATURE,
    },
    "ECC": {
        "primitive": CryptoPrimitive.UNKNOWN,
        "artefact_type": ArtefactType.UNKNOWN,
        "usage": CryptoUsage.KEY_GENERATION,
    },
    "AES": {
        "primitive": CryptoPrimitive.BLOCK_CIPHER,
        "artefact_type": ArtefactType.ENCRYPTION,
        "usage": CryptoUsage.DATA_ENCRYPTION,
    },
    "3DES": {
        "primitive": CryptoPrimitive.BLOCK_CIPHER,
        "artefact_type": ArtefactType.ENCRYPTION,
        "usage": CryptoUsage.DATA_ENCRYPTION,
    },
    "DES": {
        "primitive": CryptoPrimitive.BLOCK_CIPHER,
        "artefact_type": ArtefactType.ENCRYPTION,
        "usage": CryptoUsage.DATA_ENCRYPTION,
    },
    "MD5": {
        "primitive": CryptoPrimitive.HASH,
        "artefact_type": ArtefactType.HASH,
        "usage": CryptoUsage.INTEGRITY_HASH,
    },
    "SHA-1": {
        "primitive": CryptoPrimitive.HASH,
        "artefact_type": ArtefactType.HASH,
        "usage": CryptoUsage.INTEGRITY_HASH,
    },
    "SHA-256": {
        "primitive": CryptoPrimitive.HASH,
        "artefact_type": ArtefactType.HASH,
        "usage": CryptoUsage.INTEGRITY_HASH,
    },
    "SHA-384": {
        "primitive": CryptoPrimitive.HASH,
        "artefact_type": ArtefactType.HASH,
        "usage": CryptoUsage.INTEGRITY_HASH,
    },
    "SHA-512": {
        "primitive": CryptoPrimitive.HASH,
        "artefact_type": ArtefactType.HASH,
        "usage": CryptoUsage.INTEGRITY_HASH,
    },
    # ── Elliptic-curve algorithms exposed by Java / JS / Go crypto APIs ──
    # Ed25519 / Ed448 are EdDSA signatures on Edwards curves.
    # X25519 / X448 are ECDH key agreement on Montgomery curves.
    # All four are elliptic-curve based and therefore Shor-breakable.
    "Ed25519": {
        "primitive": CryptoPrimitive.SIGNATURE,
        "artefact_type": ArtefactType.SIGNATURE,
        "usage": CryptoUsage.DIGITAL_SIGNATURE,
    },
    "Ed448": {
        "primitive": CryptoPrimitive.SIGNATURE,
        "artefact_type": ArtefactType.SIGNATURE,
        "usage": CryptoUsage.DIGITAL_SIGNATURE,
    },
    "X25519": {
        "primitive": CryptoPrimitive.KEY_AGREE,
        "artefact_type": ArtefactType.KEY_EXCHANGE,
        "usage": CryptoUsage.KEY_ESTABLISHMENT,
    },
    "X448": {
        "primitive": CryptoPrimitive.KEY_AGREE,
        "artefact_type": ArtefactType.KEY_EXCHANGE,
        "usage": CryptoUsage.KEY_ESTABLISHMENT,
    },
    # ── Legacy DSA — Java KeyPairGenerator "DSA" pattern ──
    "DSA": {
        "primitive": CryptoPrimitive.SIGNATURE,
        "artefact_type": ArtefactType.SIGNATURE,
        "usage": CryptoUsage.DIGITAL_SIGNATURE,
    },
    # ── Modern symmetric primitives from Go / Node / WebCrypto ──
    "ChaCha20": {
        "primitive": CryptoPrimitive.STREAM_CIPHER,
        "artefact_type": ArtefactType.ENCRYPTION,
        "usage": CryptoUsage.DATA_ENCRYPTION,
    },
}

# ── Crypto function → usage refinement ───────────────────────────────────
_FUNCTION_USAGE: dict[str, CryptoUsage] = {
    "encrypt": CryptoUsage.DATA_ENCRYPTION,
    "decrypt": CryptoUsage.DATA_ENCRYPTION,
    "keygen": CryptoUsage.KEY_GENERATION,
    "sign": CryptoUsage.DIGITAL_SIGNATURE,
    "verify": CryptoUsage.DIGITAL_SIGNATURE,
    "keyderive": CryptoUsage.KEY_ESTABLISHMENT,
    "digest": CryptoUsage.INTEGRITY_HASH,
}

# ── Mode mapping ─────────────────────────────────────────────────────────
_MODE_MAP: dict[str, CipherMode] = {
    "cbc": CipherMode.CBC,
    "gcm": CipherMode.GCM,
    "ecb": CipherMode.ECB,
    "ctr": CipherMode.CTR,
    "cfb": CipherMode.CFB,
    "ofb": CipherMode.OFB,
    "ccm": CipherMode.CCM,
}

# ── Curve name extraction ────────────────────────────────────────────────
_CURVE_NAMES: dict[str, str] = {
    "secp256r1": "secp256r1",
    "SECP256R1": "secp256r1",
    "secp384r1": "secp384r1",
    "SECP384R1": "secp384r1",
    "secp521r1": "secp521r1",
    "SECP521R1": "secp521r1",
    "X25519": "x25519",
    "Ed25519": "ed25519",
}


# ═══════════════════════════════════════════════════════════════════════════
# AST helpers — parameter resolution with module-boundary policy
# ═══════════════════════════════════════════════════════════════════════════

def _module_constants(tree: ast.Module) -> dict[str, int]:
    """Integer constants assigned at module level in THIS file."""
    found: dict[str, int] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not (isinstance(node.value, ast.Constant) and isinstance(node.value.value, int)):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                found[target.id] = node.value.value
    return found


def _imported_names(tree: ast.Module) -> dict[str, str]:
    """Names bound by import in this file, mapped to source module."""
    found: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                found[alias.asname or alias.name] = node.module or "?"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                found[alias.asname or alias.name] = alias.name
    return found


def _resolve_integer_arg(
    name: str,
    constants: dict[str, int],
    imports: dict[str, str],
) -> tuple[str | None, ParameterStatus, float, list[str]]:
    """Resolve a NAME argument to a value using the module-boundary policy.

    Returns (parameter, status, confidence_modifier, unresolved_list).
    """
    # Imported from elsewhere — not ours to resolve.
    if name in imports:
        return (
            None,
            ParameterStatus.UNRESOLVED,
            0.55,
            [name],
        )

    # Defined at module level in this file — sound to resolve.
    if name in constants:
        return (
            str(constants[name]),
            ParameterStatus.RESOLVED,
            0.95,
            [],
        )

    # Unknown origin.
    return (
        None,
        ParameterStatus.UNRESOLVED,
        0.55,
        [name],
    )


def _extract_key_size_from_call(
    call_node: ast.Call,
    constants: dict[str, int],
    imports: dict[str, str],
    keyword_name: str = "key_size",
) -> tuple[str | None, ParameterStatus, float, list[str]]:
    """Extract key size from a function call's keyword argument."""
    for kw in call_node.keywords:
        if kw.arg != keyword_name:
            continue

        # Direct integer literal.
        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
            return str(kw.value.value), ParameterStatus.RESOLVED, 0.98, []

        # A name — apply module-boundary policy.
        if isinstance(kw.value, ast.Name):
            return _resolve_integer_arg(kw.value.id, constants, imports)

        # Anything else (attribute, subscript, call, etc).
        return None, ParameterStatus.UNRESOLVED, 0.5, [keyword_name]

    return None, ParameterStatus.NOT_APPLICABLE, 0.0, []


def _extract_bit_length(
    call_node: ast.Call,
    constants: dict[str, int],
    imports: dict[str, str],
) -> tuple[str | None, ParameterStatus, float, list[str]]:
    """Extract bit_length= from AESGCM.generate_key(bit_length=N)."""
    return _extract_key_size_from_call(call_node, constants, imports, "bit_length")


def _find_curve_in_file(tree: ast.Module) -> str | None:
    """Find the EC curve used in a file by looking for ec.SECP256R1() etc."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr
            if attr_name in _CURVE_NAMES:
                return _CURVE_NAMES[attr_name]
    # Also check module-level assignments like MESH_CURVE = ec.SECP256R1()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _CURVE_NAMES:
            return _CURVE_NAMES[node.attr]
    return None


def _find_call_at_line(tree: ast.Module, line: int) -> ast.Call | None:
    """Find the ast.Call node closest to the given line number."""
    best: ast.Call | None = None
    best_distance = 999999
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and hasattr(node, "lineno"):
            distance = abs(node.lineno - line)
            if distance < best_distance:
                best = node
                best_distance = distance
    return best


# ═══════════════════════════════════════════════════════════════════════════
# Evidence snippet extraction
# ═══════════════════════════════════════════════════════════════════════════

def _read_evidence_snippet(
    source: str,
    start_offset: int,
    end_offset: int,
    start_line: int,
) -> tuple[str, list[str]]:
    """Extract the matched code snippet and surrounding context lines."""
    snippet = source[start_offset:end_offset]
    lines = source.splitlines()

    # 2 lines of context above and below.
    context_start = max(0, start_line - 3)
    context_end = min(len(lines), start_line + 3)
    context = lines[context_start:context_end]

    return snippet.strip(), context


# ═══════════════════════════════════════════════════════════════════════════
# Main extraction pipeline
# ═══════════════════════════════════════════════════════════════════════════

def _make_finding_id(check_id: str, file_path: str, line: int) -> str:
    """Generate a stable, deterministic finding ID."""
    raw = f"{check_id}:{file_path}:{line}"
    short_hash = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"CRYPTO-{short_hash}"


def extract_from_semgrep_match(
    match: dict,
    target_root: Path,
) -> NormalizedFinding | None:
    """Convert one semgrep match into a NormalizedFinding.

    Returns None for matches we intentionally skip (mode-only rules,
    incidental SHA-256 detections, etc).
    """
    check_id: str = match.get("check_id", "")
    rule_name = check_id.split(".")[-1] if "." in check_id else check_id
    file_path_raw: str = match.get("path", "")
    start = match.get("start", {})
    end = match.get("end", {})
    metadata: dict = match.get("extra", {}).get("metadata", {})

    start_line = start.get("line", 0)
    start_offset = start.get("offset", 0)
    end_offset = end.get("offset", start_offset)

    # Skip mode-only rules — they enrich algorithm findings, not standalone.
    if rule_name.startswith("blindspot-mode-"):
        return None

    # Get algorithm from rule metadata.
    algorithm = metadata.get("algorithm", "UNKNOWN")
    crypto_function = metadata.get("crypto_function", "unknown")
    library = metadata.get("library")
    rule_mode = metadata.get("mode")

    # Skip incidental SHA-256 detections (used inside OAEP, ECDSA, HKDF).
    # SHA-256 is not weak and not quantum-relevant. Including it inflates
    # findings without adding information for the judge.
    if algorithm == "SHA-256":
        return None

    # Look up defaults for this algorithm.
    defaults = ALGORITHM_DEFAULTS.get(algorithm, {})
    primitive = defaults.get("primitive", CryptoPrimitive.UNKNOWN)
    artefact_type = defaults.get("artefact_type", ArtefactType.UNKNOWN)
    usage = _FUNCTION_USAGE.get(crypto_function, defaults.get("usage", CryptoUsage.UNKNOWN))

    # Override primitive from metadata if present.
    if metadata.get("primitive"):
        try:
            primitive = CryptoPrimitive(metadata["primitive"])
        except ValueError:
            pass

    # Read the source file for evidence and AST analysis.
    file_path = Path(file_path_raw)
    if not file_path.is_absolute():
        file_path = target_root / file_path
    if not file_path.is_file():
        # Try relative to target_root.
        file_path = target_root / Path(file_path_raw).name
        if not file_path.is_file():
            logger.warning("Source file not found for evidence: %s", file_path_raw)
            return None

    # errors="replace" keeps the scan alive on files with non-UTF-8 bytes,
    # which occur in large C codebases like OpenSSL.
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("Could not read source file %s: %s", file_path, exc)
        return None
    snippet, context_lines = _read_evidence_snippet(
        source, start_offset, end_offset, start_line
    )

    # Repository-relative path for evidence.
    try:
        rel_path = file_path.relative_to(target_root)
    except ValueError:
        rel_path = file_path

    # AST analysis for parameter extraction.
    parameter: str | None = None
    parameter_status = ParameterStatus.NOT_APPLICABLE
    confidence = 0.9  # Default for direct API call detection.
    unresolved: list[str] = []
    curve: str | None = None
    mode: CipherMode | None = None

    # Only Python source is amenable to :mod:`ast`. For Java / JS / TS / Go
    # (added by the R3 rulepacks) the extractor cannot resolve parameters
    # from a Python syntax tree — but the semgrep AST match itself is still
    # strong evidence, so we keep the confidence at the high band rather
    # than penalising every non-Python finding as if it were a text match.
    # A separate per-language extractor is a later upgrade; the honest
    # interim is `parameter_status = NOT_APPLICABLE` for non-Python files
    # (the rule's own metadata carries the algorithm).
    is_python_source = file_path.suffix.lower() in (".py", ".pyi")

    try:
        if not is_python_source:
            # Skip parsing entirely; keep the high-confidence default.
            confidence = 0.88
            raise _SkipASTAnalysis
        tree = ast.parse(source)
        constants = _module_constants(tree)
        imports = _imported_names(tree)
        call_node = _find_call_at_line(tree, start_line)

        # Algorithm-specific parameter extraction.
        if algorithm == "RSA" and crypto_function == "keygen" and call_node:
            param, status, conf, unres = _extract_key_size_from_call(
                call_node, constants, imports
            )
            if status != ParameterStatus.NOT_APPLICABLE:
                parameter = param
                parameter_status = status
                confidence = conf
                unresolved = unres

        elif algorithm == "AES" and crypto_function == "keygen" and call_node:
            param, status, conf, unres = _extract_bit_length(
                call_node, constants, imports
            )
            if status != ParameterStatus.NOT_APPLICABLE:
                parameter = param
                parameter_status = status
                confidence = conf
                unresolved = unres

        # Curve extraction for ECC/ECDH/ECDSA.
        if algorithm in ("ECC", "ECDH", "ECDSA"):
            curve = _find_curve_in_file(tree)
            if curve:
                parameter = curve.upper().replace("SECP", "P-").replace("R1", "")
                # Fix: secp256r1 -> P-256
                curve_to_param = {
                    "secp256r1": "P-256",
                    "secp384r1": "P-384",
                    "secp521r1": "P-521",
                    "x25519": "X25519",
                    "ed25519": "Ed25519",
                }
                parameter = curve_to_param.get(curve, curve)
                parameter_status = ParameterStatus.RESOLVED

        # Mode from rule metadata or from nearby mode-rule matches.
        if rule_mode:
            mode = _MODE_MAP.get(rule_mode)

    except _SkipASTAnalysis:
        # Deliberate skip for non-Python source; confidence already set.
        pass
    except SyntaxError:
        logger.warning("Could not parse %s for AST extraction.", rel_path)
        confidence = 0.7

    # Refine usage for RSA encrypt specifically.
    if algorithm == "RSA" and crypto_function == "encrypt":
        usage = CryptoUsage.DATA_ENCRYPTION
        artefact_type = ArtefactType.ENCRYPTION

    # Refine ECC based on what we actually detected.
    if algorithm == "ECC":
        # ec.generate_private_key — could be ECDH or ECDSA. Leave as ECC
        # keygen; the ECDH/ECDSA rules will produce their own findings.
        pass

    # Build the evidence.
    evidence = Evidence(
        file_path=str(rel_path),
        line_number=start_line,
        end_line_number=end.get("line"),
        code_snippet=snippet,
        context_lines=context_lines,
        detection_method=DetectionMethod.SEMGREP_API_PATTERN,
        confidence=confidence,
        rule_id=rule_name,
    )

    finding_id = _make_finding_id(check_id, str(rel_path), start_line)

    return NormalizedFinding(
        id=finding_id,
        algorithm=algorithm,
        primitive=primitive,
        parameter=parameter,
        parameter_status=parameter_status,
        mode=mode,
        curve=curve,
        usage=usage,
        artefact_type=artefact_type,
        library=library,
        evidence=evidence,
        unresolved_parameters=unresolved,
    )


def extract_from_dependency(dep: dict, target_root: Path) -> list[NormalizedFinding]:
    """Convert one dependency parser result into NormalizedFindings.

    One finding per algorithm the package provides.
    """
    findings: list[NormalizedFinding] = []
    package = dep.get("package", "unknown")
    version = dep.get("version")
    file_path = dep.get("file_path", "requirements.txt")
    line_number = dep.get("line_number", 1)
    base_confidence = dep.get("confidence", 0.5)
    provides = dep.get("provides", [])

    try:
        rel_path = Path(file_path).relative_to(target_root)
    except (ValueError, TypeError):
        rel_path = Path(file_path).name

    display_name = f"{package}=={version}" if version else package

    for algo in provides:
        defaults = ALGORITHM_DEFAULTS.get(algo, {})

        evidence = Evidence(
            file_path=str(rel_path),
            line_number=line_number,
            code_snippet=dep.get("raw_line", f"{display_name} (provides {algo})"),
            context_lines=[],
            detection_method=DetectionMethod.DEPENDENCY_MANIFEST,
            confidence=base_confidence,
            rule_id=f"dep-{package}",
        )

        finding_id = _make_finding_id(f"dep-{package}-{algo}", str(rel_path), line_number)

        findings.append(NormalizedFinding(
            id=finding_id,
            algorithm=algo,
            primitive=defaults.get("primitive", CryptoPrimitive.UNKNOWN),
            parameter=None,
            parameter_status=ParameterStatus.NOT_APPLICABLE,
            usage=CryptoUsage.UNKNOWN,
            artefact_type=defaults.get("artefact_type", ArtefactType.UNKNOWN),
            library=package,
            evidence=evidence,
            unresolved_parameters=[],
        ))

    return findings


def normalize(
    semgrep_matches: list[dict],
    dependency_findings: list[dict],
    target_root: Path,
) -> list[NormalizedFinding]:
    """Convert all raw scanner output into normalized findings.

    This is the boundary that protects every downstream stage from
    scanner-specific formats.
    """
    findings: list[NormalizedFinding] = []
    seen_ids: set[str] = set()

    # First pass: collect mode detections per file so we can enrich
    # algorithm findings with the modes used nearby.
    modes_by_file: dict[str, set[CipherMode]] = {}
    for match in semgrep_matches:
        check_id = match.get("check_id", "")
        rule_name = check_id.split(".")[-1] if "." in check_id else check_id
        if rule_name.startswith("blindspot-mode-"):
            metadata = match.get("extra", {}).get("metadata", {})
            mode_str = metadata.get("mode")
            file_path = match.get("path", "")
            if mode_str and mode_str in _MODE_MAP:
                modes_by_file.setdefault(file_path, set()).add(_MODE_MAP[mode_str])

    # Process semgrep matches.
    for match in semgrep_matches:
        finding = extract_from_semgrep_match(match, target_root)
        if finding and finding.id not in seen_ids:
            # Enrich with mode from same-file mode detections if not already set.
            if finding.mode is None:
                file_modes = modes_by_file.get(match.get("path", ""), set())
                if len(file_modes) == 1:
                    # Unambiguous: only one mode in the file.
                    finding = finding.model_copy(update={"mode": file_modes.pop()})
                elif len(file_modes) > 1:
                    # Multiple modes — pick the most concerning for the primary finding.
                    # ECB > CBC > others for weak-mode prioritization.
                    priority = [CipherMode.ECB, CipherMode.CBC, CipherMode.GCM,
                                CipherMode.CTR, CipherMode.CFB, CipherMode.OFB]
                    for m in priority:
                        if m in file_modes:
                            finding = finding.model_copy(update={"mode": m})
                            break

            findings.append(finding)
            seen_ids.add(finding.id)

    # Process dependency findings.
    for dep in dependency_findings:
        for finding in extract_from_dependency(dep, target_root):
            if finding.id not in seen_ids:
                findings.append(finding)
                seen_ids.add(finding.id)

    logger.info(
        "Normalization complete: %d findings (%d from source, %d from dependencies).",
        len(findings),
        sum(1 for f in findings if f.evidence.detection_method != DetectionMethod.DEPENDENCY_MANIFEST),
        sum(1 for f in findings if f.evidence.detection_method == DetectionMethod.DEPENDENCY_MANIFEST),
    )

    return findings
