"""Migration recommendation models.

The recommender is deterministic and explainable. Every recommendation names a
strategy, a concrete target algorithm, a parameter set, and the reasoning that
produced it — so a reviewer can disagree with the conclusion on its merits
rather than guessing at the logic.
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from app.models.base import BlindspotModel


class MigrationStrategy(str, Enum):
    """What the organisation should actually do about this finding."""

    PQC = "PQC"
    """Migrate to post-quantum cryptography now. Driven by an overdue tier."""

    HYBRID = "HYBRID"
    """Deploy classical + PQC together as a transition path."""

    DEFER = "DEFER"
    """Monitor. Migration is not yet warranted for this finding."""

    REMEDIATE_NOW = "REMEDIATE_NOW"
    """Fix a present-day weakness. Not a quantum recommendation."""

    INVESTIGATE = "INVESTIGATE"
    """Parameters could not be resolved; a human must confirm before deciding."""


class LatencyProfile(BlindspotModel):
    """Reference-benchmark latency for a PQC/hybrid target.

    The PS asks for recommendations "based on risk profile, latency, cost." We
    address the *latency* dimension deliberately as a **reference profile**,
    not a measurement made on this deployment. Every value here comes from a
    named published source (the CRYSTALS submissions, Cloudflare's PQC
    experiments, liboqs benchmarks, etc.), and every profile carries a
    ``platform_note`` that names the hardware / implementation the numbers
    were measured on.

    Rules that keep this honest:

    1. **Never presented as this system's measured latency.** The UI and API
       consistently render this as "reference latency (source: ...)".
    2. **Cycle counts are the primary unit.** Cycles are portable across
       clock rates; ``approx_microseconds`` is derived by dividing by a
       stated reference clock rate that ``platform_note`` calls out.
    3. **Relative bands trump precise numbers.** Real deployments differ
       widely; a coarse ``low/moderate/high`` band communicates the
       operational picture without over-promising precision.
    4. **Signatures split sign vs. verify.** Verification is often 3-5x
       faster than signing; collapsing the two into one number loses the
       most important operational signal.
    """

    target: str = Field(description="PQC target the profile describes, e.g. 'ML-KEM-768'.")

    # KEM operations. All fields optional; the recommender fills only the
    # ones that make sense for the primitive.
    keygen_cycles: int | None = Field(default=None, description="Reference key-generation cost, CPU cycles.")
    encapsulate_cycles: int | None = Field(default=None, description="Reference KEM encapsulation cost, CPU cycles.")
    decapsulate_cycles: int | None = Field(default=None, description="Reference KEM decapsulation cost, CPU cycles.")

    # Signature operations.
    sign_cycles: int | None = Field(default=None, description="Reference signing cost, CPU cycles.")
    verify_cycles: int | None = Field(default=None, description="Reference verification cost, CPU cycles.")

    # Compared to the classical primitive being replaced (best-effort).
    classical_sign_cycles: int | None = Field(default=None, description="Approx. classical signing cost for comparison.")
    classical_verify_cycles: int | None = Field(default=None, description="Approx. classical verification cost for comparison.")
    classical_encapsulate_cycles: int | None = Field(default=None, description="Approx. classical encapsulation cost.")
    classical_decapsulate_cycles: int | None = Field(default=None, description="Approx. classical decapsulation cost.")

    # TLS handshake overhead where measured (Cloudflare / IETF papers).
    handshake_extra_bytes: int | None = Field(
        default=None,
        description="Approximate additional TLS ClientHello/ServerHello bytes for a hybrid handshake.",
    )
    handshake_extra_bytes_source: str | None = Field(default=None)

    relative_latency: str = Field(
        default="moderate",
        description="Coarse latency band relative to typical classical baseline: low | moderate | high.",
    )
    summary: str = Field(
        description="Plain-language one-sentence latency picture, e.g. 'ML-KEM-768 keygen/encaps/decaps run in tens of microseconds on modern x86-64 with AVX2.'",
    )
    platform_note: str = Field(
        description=(
            "The hardware / implementation the reference cycle counts were "
            "measured on. Explicitly disclaims that this is not a measurement "
            "on the scanned system."
        ),
    )
    basis: str = Field(
        default=(
            "Reference-implementation benchmarks from the algorithm authors' "
            "published papers - not runtime latency measured on this system."
        ),
        description="What these numbers are (and are not).",
    )
    sources: list[str] = Field(
        default_factory=list,
        description="Cited sources for the cycle counts (papers, submissions, benchmarking projects).",
    )


class CostProfile(BlindspotModel):
    """The operational cost of a PQC/hybrid target, in *published* sizes.

    The PS asks for recommendations "based on risk profile, latency, cost." We
    express cost as the concrete artefact sizes standardised in the FIPS specs —
    public key, ciphertext, and signature bytes — versus the classical algorithm
    being replaced. These are **published parameter sizes, not measured
    latency**: real latency depends on hardware, network, and implementation, so
    we do not invent millisecond figures. Larger keys/ciphertexts are the honest,
    citable proxy for the bandwidth, storage, and handshake cost of migrating.
    """

    target: str = Field(description="PQC target the sizes describe, e.g. 'ML-KEM-768'.")
    public_key_bytes: int | None = Field(default=None, description="PQC public/encapsulation key size.")
    ciphertext_bytes: int | None = Field(default=None, description="KEM ciphertext size (KEMs only).")
    signature_bytes: int | None = Field(default=None, description="Signature size (signatures only).")
    private_key_bytes: int | None = Field(default=None, description="PQC private/decapsulation key size.")
    classical_public_key_bytes: int | None = Field(
        default=None, description="Approx. classical public-key size being replaced."
    )
    classical_signature_bytes: int | None = Field(
        default=None, description="Approx. classical signature size being replaced."
    )
    relative_cost: str = Field(
        default="moderate",
        description="Coarse cost band from artefact size: low | moderate | high.",
    )
    size_summary: str = Field(
        description="Plain-language size comparison vs. the classical algorithm."
    )
    basis: str = Field(
        default="Published FIPS parameter sizes in bytes — not measured runtime latency.",
        description="What these numbers are (and are not).",
    )
    sources: list[str] = Field(
        default_factory=list, description="Standards the sizes come from."
    )


class Recommendation(BlindspotModel):
    """A single actionable recommendation for one finding."""

    strategy: MigrationStrategy
    algorithm: str = Field(
        description="Named target, e.g. 'ML-KEM-1024' or 'X25519 + ML-KEM-768'."
    )
    parameter_set: str | None = Field(
        default=None,
        description="Explicit parameter set / security category, e.g. 'ML-KEM-768 (Category 3)'.",
    )
    rationale: str = Field(
        description="Why this strategy and algorithm follow from the evidence and risk."
    )
    replaces: str | None = Field(
        default=None, description="The classical algorithm being replaced."
    )
    priority: int = Field(
        default=3,
        ge=1,
        le=5,
        description="1 = act immediately, 5 = monitor only.",
    )
    effort: str | None = Field(
        default=None, description="Rough migration effort, e.g. 'moderate'."
    )
    migration_notes: list[str] = Field(
        default_factory=list,
        description="Practical caveats: interoperability, payload size, library support.",
    )
    references: list[str] = Field(
        default_factory=list,
        description="Standards backing the target, e.g. 'NIST FIPS 203'.",
    )
    is_quantum_recommendation: bool = Field(
        default=True,
        description=(
            "False for REMEDIATE_NOW findings, which address a current "
            "weakness rather than quantum migration urgency."
        ),
    )
    cost_profile: CostProfile | None = Field(
        default=None,
        description=(
            "Size/cost profile of the PQC target (published FIPS sizes). Present "
            "for PQC and HYBRID recommendations; None where there is no PQC target."
        ),
    )
    latency_profile: LatencyProfile | None = Field(
        default=None,
        description=(
            "Reference latency profile of the PQC target, drawn from cited "
            "published benchmarks. Always presented as reference-only; never "
            "as this system's measured latency."
        ),
    )
