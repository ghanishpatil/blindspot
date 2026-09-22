"""Policy-as-code REST endpoints.

Surfaces the CLI's policy engine (:mod:`app.cli.policy`) as a first-class
API resource so the dashboard can view, edit, reset, and simulate the
same policy that ``blindspot-scan gate`` runs in CI. One source of truth,
two consumers.

Contract:

* ``GET  /api/policy``          -- current active policy (default when
                                   nothing has been saved).
* ``GET  /api/policy/default``  -- the built-in default policy. Read-only.
* ``PUT  /api/policy``          -- validate + persist. 400 on schema error.
* ``POST /api/policy/reset``    -- delete the override, revert to default.
* ``POST /api/policy/simulate`` -- given a policy body + ``base`` /
                                   ``head`` scan ids, compute the delta
                                   and return the policy's violations
                                   without persisting anything.

Owner scoping matches ``GET /api/scans/{id}``: a policy simulation can
only reach scans the caller is authorised to see. There is no separate
"policies list" -- one active policy per install, as documented in
:mod:`app.policy.store`.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.scans_diff import _load_visible_scan
from app.cli.diff import compute_delta
from app.cli.policy import (
    DEFAULT_POLICY,
    POLICY_SCHEMA_VERSION,
    PolicyError,
    evaluate_policy,
    parse_policy_dict,
    policy_to_dict,
)
from app.config import Settings, get_settings
from app.firebase.auth import CurrentUser
from app.policy.store import PolicyStore, get_default_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/policy", tags=["policy"])


# ---------------------------------------------------------------------------
# Store injection -- lets tests swap in an in-memory / temp-dir store
# without monkeypatching module-level globals.
# ---------------------------------------------------------------------------

def _resolve_store() -> PolicyStore:
    """FastAPI dependency returning the process-wide policy store."""
    return get_default_store()


StoreDep = Annotated[PolicyStore, Depends(_resolve_store)]


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class PolicyEnvelope(BaseModel):
    """Response wrapper for ``GET`` endpoints."""

    schemaVersion: str = Field(default=POLICY_SCHEMA_VERSION)
    isDefault: bool = Field(
        description=(
            "True when the returned policy is the built-in default -- "
            "no override has been persisted for this install."
        ),
    )
    policy: dict[str, Any] = Field(
        description="Full policy JSON. Round-trips through PUT /api/policy.",
    )


class SimulationRequest(BaseModel):
    """Body for ``POST /api/policy/simulate``.

    The ``policy`` is optional: omit it and we evaluate the *currently
    active* policy against the delta. That's the fast path for
    "will my current policy fire on this pair of scans?".
    """

    base: str = Field(description="Baseline scan id.")
    head: str = Field(description="Candidate scan id.")
    policy: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Optional policy JSON to simulate. When omitted, the "
            "currently active policy is used."
        ),
    )


class SimulationResponse(BaseModel):
    """Response body for ``POST /api/policy/simulate``."""

    policyName: str
    counts: dict[str, int]
    violations: list[dict[str, Any]]
    blockCount: int
    warnCount: int
    wouldBlock: bool = Field(
        description=(
            "Convenience: true iff this policy would exit 2 in CI "
            "against this delta. Equivalent to blockCount > 0."
        ),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", summary="Get the currently active policy")
async def get_policy(
    _user: CurrentUser,
    store: StoreDep,
) -> PolicyEnvelope:
    """Return the active policy, or the built-in default.

    We surface ``isDefault`` so the UI can flag "using built-in
    defaults" versus "using a customised policy" without diffing the
    payload itself.
    """
    try:
        policy = store.get()
    except PolicyError as exc:
        # Persisted file was hand-edited into an invalid state. Refuse
        # to serve a broken policy silently -- the operator needs to
        # see this.
        logger.exception("active policy file failed to load")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Active policy file is corrupt: {exc}",
        ) from exc
    return PolicyEnvelope(
        isDefault=not store.has_override(),
        policy=policy_to_dict(policy),
    )


@router.get("/default", summary="Get the built-in default policy")
async def get_default_policy(_user: CurrentUser) -> PolicyEnvelope:
    """Read-only surface. Used by the UI's 'restore defaults' preview."""
    return PolicyEnvelope(
        isDefault=True,
        policy=policy_to_dict(DEFAULT_POLICY),
    )


@router.put("", summary="Save a new active policy")
async def put_policy(
    payload: dict[str, Any],
    _user: CurrentUser,
    store: StoreDep,
) -> PolicyEnvelope:
    """Validate and persist a policy JSON body.

    Any :class:`PolicyError` from schema validation surfaces as HTTP
    400 with the exact reason -- callers must see *why* the payload
    was rejected, not just that it was.
    """
    try:
        saved = store.save(payload)
    except PolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    return PolicyEnvelope(
        isDefault=False,
        policy=policy_to_dict(saved),
    )


@router.post("/reset", summary="Reset to the built-in default policy")
async def reset_policy(
    _user: CurrentUser,
    store: StoreDep,
) -> PolicyEnvelope:
    """Delete the override file. Idempotent."""
    reverted = store.reset()
    return PolicyEnvelope(
        isDefault=True,
        policy=policy_to_dict(reverted),
    )


@router.post(
    "/simulate",
    summary="Evaluate a policy against two scans without persisting",
)
async def simulate_policy(
    body: SimulationRequest,
    user: CurrentUser,
    settings: Annotated[Settings, Depends(get_settings)],
    store: StoreDep,
) -> SimulationResponse:
    """Compute the delta between ``base`` and ``head`` and run a policy.

    Behavior:

    * ``body.policy`` present  -> validate + evaluate that policy.
    * ``body.policy`` omitted  -> evaluate the currently active policy.

    Never persists; this is the "would my rule change block this PR?"
    endpoint. Uses the CLI's :func:`compute_delta` so the answer here
    matches ``blindspot-scan gate`` byte-for-byte.
    """
    if body.base == body.head:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="base and head must be different scan ids.",
        )

    # 1. Pick the policy to evaluate.
    if body.policy is not None:
        try:
            policy = parse_policy_dict(body.policy)
        except PolicyError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
    else:
        try:
            policy = store.get()
        except PolicyError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Active policy file is corrupt: {exc}",
            ) from exc

    # 2. Load both sides. Same owner-scoping as GET /scans/diff.
    base_loaded = _load_visible_scan(body.base, user, settings)
    if base_loaded is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scan with id {body.base!r} was found on the local mirror.",
        )
    head_loaded = _load_visible_scan(body.head, user, settings)
    if head_loaded is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scan with id {body.head!r} was found on the local mirror.",
        )

    _, base_findings = base_loaded
    _, head_findings = head_loaded

    # 3. Delta + evaluate. compute_delta is pure; evaluate_policy is
    #    pure; nothing here writes to disk or Firebase.
    delta = compute_delta(base_findings, head_findings)
    violations = evaluate_policy(policy, delta)

    block_count = sum(1 for v in violations if v.action == "block")
    warn_count = sum(1 for v in violations if v.action == "warn")

    return SimulationResponse(
        policyName=policy.name,
        counts={
            "introduced": len(delta.introduced),
            "resolved": len(delta.resolved),
            "changed": len(delta.changed),
            "unchanged": delta.unchanged_count,
        },
        violations=[v.to_dict() for v in violations],
        blockCount=block_count,
        warnCount=warn_count,
        wouldBlock=block_count > 0,
    )
