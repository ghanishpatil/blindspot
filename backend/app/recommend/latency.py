"""Reference-latency profiles for PQC targets (R5).

The problem statement lists *latency* as one of the axes on which
recommendations must weigh a migration target. This module answers that
requirement with **cited reference benchmarks** rather than inventing
runtime numbers.

Two rules keep the module honest:

1. **Every value is sourced.** Every cycle count carries a citation string
   naming the paper, submission, or benchmark suite it came from. The
   ``sources`` list on :class:`LatencyProfile` is not decorative.
2. **The platform is always named.** ``platform_note`` on every profile
   explicitly disclaims that these numbers were not measured on the
   scanned system. The UI is required to render this disclaimer alongside
   any latency number it shows.

The numbers below are pulled from the algorithm authors' published
performance tables (round-3 CRYSTALS submissions, Cloudflare / Google TLS
measurement papers, liboqs benchmarks). Cycle counts vary widely between
reference and optimised implementations; we pick the widely-cited AVX2
optimised numbers because they represent what a modern x86-64 deployment
will actually see when using a hardware-accelerated crypto library.

**Sources**

* CRYSTALS-Kyber, "Round 3 submission to NIST PQC", performance appendix,
  AVX2 optimised implementation on Intel Skylake i7-6600U @ 2.6 GHz.
* CRYSTALS-Dilithium, "Round 3 submission to NIST PQC", performance
  appendix, AVX2 optimised implementation on Intel Skylake.
* Open Quantum Safe project (liboqs) benchmarking documentation.
* Cloudflare, "Sizing Up Post-Quantum Signatures" (2021) - TLS handshake
  overhead measurements.
* Google, "Combining classical and post-quantum key exchange in TLS 1.3"
  measurement notes.
* Classical baselines: standard ``openssl speed`` output on the same
  reference platform, widely cited for cross-comparison.
"""

from __future__ import annotations

from app.models.recommendation import LatencyProfile

# =============================================================================
# Shared platform + citation strings so multiple profiles cite the same source
# in a byte-identical way, keeping any future audit of "did we invent this?"
# trivial (one string, one source).
# =============================================================================

_SKYLAKE_PLATFORM_NOTE = (
    "Intel Skylake i7-6600U @ 2.6 GHz (AVX2 optimised reference implementation "
    "from the algorithm authors) - not measured on the scanned system."
)

_KYBER_R3_SOURCE = (
    "CRYSTALS-Kyber, Round 3 submission to NIST PQC (2020), performance "
    "appendix, AVX2 optimised, Skylake i7-6600U. ML-KEM (FIPS 203) is the "
    "final standardisation of this design."
)

_DILITHIUM_R3_SOURCE = (
    "CRYSTALS-Dilithium, Round 3 submission to NIST PQC (2020), performance "
    "appendix, AVX2 optimised, Skylake i7-6600U. ML-DSA (FIPS 204) is the "
    "final standardisation of this design."
)

_CLOUDFLARE_HANDSHAKE_SOURCE = (
    "Cloudflare, 'Sizing Up Post-Quantum Signatures' (Oct 2021), TLS 1.3 "
    "ClientHello / ServerHello overhead measurements."
)


# =============================================================================
# ML-KEM (FIPS 203) - Kyber round-3 optimised numbers.
# =============================================================================

_ML_KEM_512 = LatencyProfile(
    target="ML-KEM-512",
    keygen_cycles=33_000,
    encapsulate_cycles=45_000,
    decapsulate_cycles=34_000,
    # Classical baseline: ECDH P-256 on the same reference platform.
    classical_encapsulate_cycles=112_000,
    classical_decapsulate_cycles=112_000,
    relative_latency="low",
    summary=(
        "ML-KEM-512 keygen/encaps/decaps each complete in tens of microseconds "
        "on modern x86-64 with AVX2; typically faster than ECDH P-256 on the "
        "same platform."
    ),
    platform_note=_SKYLAKE_PLATFORM_NOTE,
    sources=[_KYBER_R3_SOURCE],
)

_ML_KEM_768 = LatencyProfile(
    target="ML-KEM-768",
    keygen_cycles=52_000,
    encapsulate_cycles=68_000,
    decapsulate_cycles=54_000,
    classical_encapsulate_cycles=112_000,
    classical_decapsulate_cycles=112_000,
    handshake_extra_bytes=1_100,
    handshake_extra_bytes_source=_CLOUDFLARE_HANDSHAKE_SOURCE,
    relative_latency="low",
    summary=(
        "ML-KEM-768 keygen/encaps/decaps each complete in the low tens of "
        "microseconds; a hybrid TLS handshake adds approximately 1 KB to "
        "ClientHello/ServerHello per Cloudflare's measurements."
    ),
    platform_note=_SKYLAKE_PLATFORM_NOTE,
    sources=[_KYBER_R3_SOURCE, _CLOUDFLARE_HANDSHAKE_SOURCE],
)

_ML_KEM_1024 = LatencyProfile(
    target="ML-KEM-1024",
    keygen_cycles=74_000,
    encapsulate_cycles=96_000,
    decapsulate_cycles=79_000,
    classical_encapsulate_cycles=112_000,
    classical_decapsulate_cycles=112_000,
    handshake_extra_bytes=1_600,
    handshake_extra_bytes_source=_CLOUDFLARE_HANDSHAKE_SOURCE,
    relative_latency="moderate",
    summary=(
        "ML-KEM-1024 keygen/encaps/decaps each complete under 100 microseconds "
        "on the reference platform; hybrid handshake adds ~1.5 KB per "
        "Cloudflare's measurements."
    ),
    platform_note=_SKYLAKE_PLATFORM_NOTE,
    sources=[_KYBER_R3_SOURCE, _CLOUDFLARE_HANDSHAKE_SOURCE],
)


# =============================================================================
# ML-DSA (FIPS 204) - Dilithium round-3 optimised numbers.
# =============================================================================

_ML_DSA_44 = LatencyProfile(
    target="ML-DSA-44",
    keygen_cycles=130_000,
    sign_cycles=333_000,
    verify_cycles=118_000,
    # Classical baseline: ECDSA P-256 on the same reference platform.
    classical_sign_cycles=100_000,
    classical_verify_cycles=350_000,
    relative_latency="moderate",
    summary=(
        "ML-DSA-44 verify is comparable to ECDSA P-256 verify; sign is roughly "
        "3x slower than ECDSA P-256 sign on the reference platform."
    ),
    platform_note=_SKYLAKE_PLATFORM_NOTE,
    sources=[_DILITHIUM_R3_SOURCE],
)

_ML_DSA_65 = LatencyProfile(
    target="ML-DSA-65",
    keygen_cycles=210_000,
    sign_cycles=530_000,
    verify_cycles=179_000,
    classical_sign_cycles=100_000,
    classical_verify_cycles=350_000,
    handshake_extra_bytes=3_500,
    handshake_extra_bytes_source=_CLOUDFLARE_HANDSHAKE_SOURCE,
    relative_latency="moderate",
    summary=(
        "ML-DSA-65 sign is roughly 5x slower than ECDSA P-256 sign on the "
        "reference platform; verify remains fast (sub-100 us). Signatures are "
        "much larger (~3.3 KB) so the dominant TLS cost is bandwidth, not CPU."
    ),
    platform_note=_SKYLAKE_PLATFORM_NOTE,
    sources=[_DILITHIUM_R3_SOURCE, _CLOUDFLARE_HANDSHAKE_SOURCE],
)

_ML_DSA_87 = LatencyProfile(
    target="ML-DSA-87",
    keygen_cycles=300_000,
    sign_cycles=642_000,
    verify_cycles=279_000,
    classical_sign_cycles=100_000,
    classical_verify_cycles=350_000,
    handshake_extra_bytes=5_000,
    handshake_extra_bytes_source=_CLOUDFLARE_HANDSHAKE_SOURCE,
    relative_latency="high",
    summary=(
        "ML-DSA-87 (Category 5) sign is ~6x slower than ECDSA P-256 sign on "
        "the reference platform; verify is comparable. Signature size (~4.6 "
        "KB) dominates the TLS handshake cost."
    ),
    platform_note=_SKYLAKE_PLATFORM_NOTE,
    sources=[_DILITHIUM_R3_SOURCE, _CLOUDFLARE_HANDSHAKE_SOURCE],
)


# =============================================================================
# Lookup tables keyed by target algorithm string. `get_latency_profile` is
# the single entry point the recommender calls.
# =============================================================================

_PROFILES: dict[str, LatencyProfile] = {
    "ML-KEM-512": _ML_KEM_512,
    "ML-KEM-768": _ML_KEM_768,
    "ML-KEM-1024": _ML_KEM_1024,
    "ML-DSA-44": _ML_DSA_44,
    "ML-DSA-65": _ML_DSA_65,
    "ML-DSA-87": _ML_DSA_87,
}


def get_latency_profile(target: str) -> LatencyProfile | None:
    """Return the reference latency profile for *target*, or None if unknown.

    ``target`` matches the ``pqc`` / ``pqc_set`` strings the recommender
    already produces (e.g. ``"ML-KEM-768"``). Any prefix or suffix the
    recommender attaches (e.g. hybrid names like ``"X25519 + ML-KEM-768"``)
    is normalised by :func:`_normalise_target` first.
    """
    key = _normalise_target(target)
    return _PROFILES.get(key)


def _normalise_target(target: str) -> str:
    """Extract the ML-KEM / ML-DSA component from a possibly-hybrid target.

    Hybrid recommendations look like ``"X25519 + ML-KEM-768"``. We latency-
    profile the PQC component because that is what the reference cycle
    counts describe. The classical share adds its own cost, which is
    already captured in the ``classical_*`` fields of the profile.
    """
    if not target:
        return ""
    # Look for a token beginning with "ML-KEM-" or "ML-DSA-".
    for token in target.replace(",", " ").split():
        upper = token.strip().upper()
        for prefix in ("ML-KEM-", "ML-DSA-"):
            if upper.startswith(prefix):
                # Strip any trailing punctuation like ")" from "ML-DSA-65)".
                clean = upper.rstrip(")].,;:")
                return clean
    return target.strip()


def available_targets() -> list[str]:
    """Return every target the latency table currently covers.

    Exposed for tests and for the frontend's schema-completeness checks.
    """
    return sorted(_PROFILES.keys())
