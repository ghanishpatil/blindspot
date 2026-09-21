"""Multi-ecosystem dependency parser tests -- R4.

Every fixture is a small manifest written to ``tmp_path``. Tests are
asserted on three guarantees:

1. **Correct package matching.** Each ecosystem parser finds only the
   known crypto-providing packages in its curated table; unknown packages
   are silently ignored.
2. **Provides-list is preserved.** The ``provides`` algorithms flow through
   unchanged so downstream analysis sees the same capability set.
3. **Ecosystem isolation.** A ``pom.xml`` scan does not surface an npm
   package name; a ``go.mod`` scan does not surface a Python package.

The parsers are also exercised through the full pipeline (normalize -> enrich)
to confirm each dependency finding lands as one ``NormalizedFinding`` per
algorithm in ``provides``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.evidence.extractor import normalize
from app.models.finding import DetectionMethod
from app.scanner.dependency_parser import (
    CRYPTO_PACKAGES_GO,
    CRYPTO_PACKAGES_MAVEN,
    CRYPTO_PACKAGES_NPM,
    parse_dependencies,
)


# ── Small shared helpers ─────────────────────────────────────────────────

def _packages(deps: list[dict]) -> set[str]:
    return {d["package"] for d in deps}


def _by_package(deps: list[dict], name: str) -> dict | None:
    for d in deps:
        if d["package"] == name:
            return d
    return None


# ═════════════════════════════════════════════════════════════════════════
# Maven (pom.xml)
# ═════════════════════════════════════════════════════════════════════════

_POM_MULTI = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>0.1.0</version>
    <dependencies>
        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bcprov-jdk18on</artifactId>
            <version>1.78</version>
        </dependency>
        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bctls-jdk18on</artifactId>
            <version>1.78</version>
        </dependency>
        <dependency>
            <groupId>com.google.crypto.tink</groupId>
            <artifactId>tink</artifactId>
            <version>1.13.0</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>6.1.0</version>
        </dependency>
    </dependencies>
</project>
"""


def test_pom_xml_reports_bouncycastle_and_tink(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(_POM_MULTI, encoding="utf-8")

    deps = parse_dependencies(tmp_path)
    packages = _packages(deps)

    assert "org.bouncycastle:bcprov-jdk18on" in packages
    assert "org.bouncycastle:bctls-jdk18on" in packages
    assert "com.google.crypto.tink:tink" in packages
    # Non-crypto packages must be silently ignored.
    assert "org.springframework:spring-core" not in packages


def test_pom_xml_version_captured_when_present(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(_POM_MULTI, encoding="utf-8")

    deps = parse_dependencies(tmp_path)
    bc = _by_package(deps, "org.bouncycastle:bcprov-jdk18on")
    assert bc is not None
    assert bc["version"] == "1.78"
    assert bc["confidence"] < 0.85  # medium band, not HIGH
    assert bc["detection_method"] == "dependency_manifest"


def test_pom_xml_missing_version_yields_none(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        "<?xml version='1.0'?>"
        "<project xmlns='http://maven.apache.org/POM/4.0.0'>"
        "<dependencies>"
        "<dependency>"
        "<groupId>org.bouncycastle</groupId>"
        "<artifactId>bcprov-jdk18on</artifactId>"
        "</dependency>"
        "</dependencies>"
        "</project>",
        encoding="utf-8",
    )

    deps = parse_dependencies(tmp_path)
    bc = _by_package(deps, "org.bouncycastle:bcprov-jdk18on")
    assert bc is not None
    assert bc["version"] is None


def test_pom_xml_malformed_never_crashes(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<not-really-xml", encoding="utf-8")

    # Must not raise.
    deps = parse_dependencies(tmp_path)
    assert deps == []


def test_pom_xml_provides_includes_ed25519(tmp_path: Path) -> None:
    """R3 added Ed25519/X25519 to the risk model. R4 must expose them
    through the BouncyCastle provides list so the pipeline can classify
    them for downstream risk assessment."""
    (tmp_path / "pom.xml").write_text(_POM_MULTI, encoding="utf-8")

    deps = parse_dependencies(tmp_path)
    bc = _by_package(deps, "org.bouncycastle:bcprov-jdk18on")
    assert bc is not None
    assert "Ed25519" in bc["provides"]
    assert "X25519" in bc["provides"]


# ═════════════════════════════════════════════════════════════════════════
# npm / yarn (package.json)
# ═════════════════════════════════════════════════════════════════════════

_PACKAGE_JSON = """\
{
    "name": "demo",
    "version": "0.0.1",
    "dependencies": {
        "node-forge": "^1.3.1",
        "crypto-js": "^4.2.0",
        "tweetnacl": "^1.0.3",
        "lodash": "^4.17.21"
    },
    "devDependencies": {
        "elliptic": "^6.5.4",
        "typescript": "^5.0.0"
    },
    "peerDependencies": {
        "jose": "^5.1.0"
    }
}
"""


def test_package_json_reports_known_crypto_libs(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(_PACKAGE_JSON, encoding="utf-8")

    deps = parse_dependencies(tmp_path)
    packages = _packages(deps)

    assert {"node-forge", "crypto-js", "tweetnacl", "elliptic", "jose"}.issubset(packages)
    # Non-crypto packages must not surface.
    assert "lodash" not in packages
    assert "typescript" not in packages


def test_package_json_captures_version_ranges(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(_PACKAGE_JSON, encoding="utf-8")

    deps = parse_dependencies(tmp_path)
    forge = _by_package(deps, "node-forge")
    assert forge is not None
    assert forge["version"] == "^1.3.1"
    assert forge["confidence"] < 0.85


def test_package_json_reads_all_four_sections(tmp_path: Path) -> None:
    """dependencies, devDependencies, peerDependencies, and
    optionalDependencies must all be inspected."""
    (tmp_path / "package.json").write_text(
        '{"optionalDependencies": {"jsrsasign": "^11.0.0"}}',
        encoding="utf-8",
    )

    deps = parse_dependencies(tmp_path)
    assert "jsrsasign" in _packages(deps)


def test_package_json_malformed_never_crashes(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{ this: is not: json", encoding="utf-8")
    assert parse_dependencies(tmp_path) == []


def test_package_json_deduplicates_across_sections(tmp_path: Path) -> None:
    """A package listed in both `dependencies` and `devDependencies` must
    surface exactly once - double-counting would double the algorithm
    inventory from a single library."""
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"crypto-js": "^4.2.0"},'
        ' "devDependencies": {"crypto-js": "^4.2.0"}}',
        encoding="utf-8",
    )
    deps = parse_dependencies(tmp_path)
    assert len([d for d in deps if d["package"] == "crypto-js"]) == 1


# ═════════════════════════════════════════════════════════════════════════
# Go modules (go.mod)
# ═════════════════════════════════════════════════════════════════════════

_GO_MOD_BLOCK = """\
module example.com/demo

go 1.22

require (
    golang.org/x/crypto v0.31.0
    github.com/cloudflare/circl v1.3.7
    github.com/sirupsen/logrus v1.9.3
    filippo.io/edwards25519 v1.1.0 // indirect
)

require github.com/spf13/cobra v1.8.0
"""

_GO_MOD_BARE = """\
module example.com/demo
go 1.22
require golang.org/x/crypto v0.31.0
require github.com/google/tink/go v1.7.0
"""


def test_go_mod_block_form(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(_GO_MOD_BLOCK, encoding="utf-8")

    deps = parse_dependencies(tmp_path)
    packages = _packages(deps)

    assert "golang.org/x/crypto" in packages
    assert "github.com/cloudflare/circl" in packages
    assert "filippo.io/edwards25519" in packages
    # Non-crypto packages ignored.
    assert "github.com/sirupsen/logrus" not in packages
    assert "github.com/spf13/cobra" not in packages


def test_go_mod_bare_require_lines(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(_GO_MOD_BARE, encoding="utf-8")

    deps = parse_dependencies(tmp_path)
    packages = _packages(deps)
    assert "golang.org/x/crypto" in packages
    assert "github.com/google/tink/go" in packages


def test_go_mod_indirect_is_still_reported(tmp_path: Path) -> None:
    """`// indirect` marks a transitive dependency, but the primitives it
    provides still land on the build. Capability = capability."""
    (tmp_path / "go.mod").write_text(_GO_MOD_BLOCK, encoding="utf-8")

    deps = parse_dependencies(tmp_path)
    filippo = _by_package(deps, "filippo.io/edwards25519")
    assert filippo is not None
    assert filippo["version"] == "v1.1.0"


def test_go_mod_captures_version(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(_GO_MOD_BLOCK, encoding="utf-8")

    deps = parse_dependencies(tmp_path)
    xcrypto = _by_package(deps, "golang.org/x/crypto")
    assert xcrypto is not None
    assert xcrypto["version"] == "v0.31.0"
    assert xcrypto["confidence"] < 0.85


# ═════════════════════════════════════════════════════════════════════════
# Cross-cutting behaviour
# ═════════════════════════════════════════════════════════════════════════

def test_parser_ignores_node_modules(tmp_path: Path) -> None:
    """Installed dependencies live under `node_modules/*/package.json`. If
    we recursed into them we would multiply findings by the size of the
    dep tree. R4 must skip those directories entirely."""
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"node-forge": "^1.3.1"}}',
        encoding="utf-8",
    )
    nested = tmp_path / "node_modules" / "some-lib"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text(
        '{"dependencies": {"crypto-js": "^4.2.0"}}',
        encoding="utf-8",
    )

    deps = parse_dependencies(tmp_path)
    packages = _packages(deps)
    assert "node-forge" in packages
    assert "crypto-js" not in packages, (
        "package.json under node_modules/ must not be re-parsed"
    )


def test_parser_ignores_target_directory(tmp_path: Path) -> None:
    """Maven puts a copy of pom.xml under target/. Skip it for the same
    reason as node_modules."""
    (tmp_path / "pom.xml").write_text(_POM_MULTI, encoding="utf-8")
    build = tmp_path / "target" / "classes"
    build.mkdir(parents=True)
    (build / "pom.xml").write_text(_POM_MULTI, encoding="utf-8")

    deps = parse_dependencies(tmp_path)
    # Exactly one instance per known crypto coordinate.
    counts: dict[str, int] = {}
    for d in deps:
        counts[d["package"]] = counts.get(d["package"], 0) + 1
    for pkg, count in counts.items():
        assert count == 1, f"{pkg} was reported {count} times"


def test_all_ecosystems_together(tmp_path: Path) -> None:
    """A polyglot project with all four manifest types must produce
    findings from every ecosystem in one scan."""
    (tmp_path / "requirements.txt").write_text("cryptography==42.0.0\n", encoding="utf-8")
    (tmp_path / "pom.xml").write_text(_POM_MULTI, encoding="utf-8")
    (tmp_path / "package.json").write_text(_PACKAGE_JSON, encoding="utf-8")
    (tmp_path / "go.mod").write_text(_GO_MOD_BLOCK, encoding="utf-8")

    deps = parse_dependencies(tmp_path)
    packages = _packages(deps)

    assert "cryptography" in packages
    assert "org.bouncycastle:bcprov-jdk18on" in packages
    assert "node-forge" in packages
    assert "golang.org/x/crypto" in packages


def test_findings_flow_through_normalize(tmp_path: Path) -> None:
    """The final proof: dependency parser output must lift into
    NormalizedFinding via the existing evidence extractor without any
    per-ecosystem branching."""
    (tmp_path / "package.json").write_text(_PACKAGE_JSON, encoding="utf-8")

    deps = parse_dependencies(tmp_path)
    findings = normalize([], deps, tmp_path)

    # Every finding must carry the DEPENDENCY_MANIFEST detection method and
    # medium confidence.
    assert findings
    for f in findings:
        assert f.evidence.detection_method == DetectionMethod.DEPENDENCY_MANIFEST
        assert f.evidence.confidence < 0.85

    # tweetnacl provides Ed25519 + X25519 - both quantum-vulnerable per R3.
    tweetnacl_algos = {
        f.algorithm for f in findings if f.library == "tweetnacl"
    }
    assert {"Ed25519", "X25519"}.issubset(tweetnacl_algos)


def test_curated_tables_stay_medium_confidence() -> None:
    """No curated crypto library may claim HIGH-band confidence. A
    dependency is capability, not observation."""
    for name, info in {
        **CRYPTO_PACKAGES_MAVEN,
        **CRYPTO_PACKAGES_NPM,
        **CRYPTO_PACKAGES_GO,
    }.items():
        assert info["confidence"] < 0.85, (
            f"{name} has confidence {info['confidence']} >= 0.85 (HIGH band)"
        )
        assert info["provides"], f"{name} has empty provides list"


def test_curated_tables_use_known_algorithms() -> None:
    """Every algorithm in every provides list must be one the risk model
    knows how to classify. An unknown algorithm string would surface as
    an inventoried finding with no quantum-risk assessment - which is
    exactly the dishonest state R3/R4 must not create."""
    from app.evidence.extractor import ALGORITHM_DEFAULTS

    known = set(ALGORITHM_DEFAULTS.keys())
    all_tables = {
        **CRYPTO_PACKAGES_MAVEN,
        **CRYPTO_PACKAGES_NPM,
        **CRYPTO_PACKAGES_GO,
    }
    for pkg, info in all_tables.items():
        for algo in info["provides"]:
            assert algo in known, (
                f"{pkg} claims to provide {algo!r} but ALGORITHM_DEFAULTS "
                f"does not know how to classify it. Either add it to the "
                f"defaults table or remove it from the provides list."
            )
