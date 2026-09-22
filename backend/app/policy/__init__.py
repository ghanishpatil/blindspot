"""Policy service layer.

The pure schema, evaluator, and default live in :mod:`app.cli.policy`
so the CLI can be shipped without importing the FastAPI stack. This
package adds the persistence and simulation concerns the REST API
needs -- storage, active-policy lifecycle, and delta simulation on
top of the existing scan history.

Layout:

* :mod:`app.policy.store` -- file-backed active-policy storage under
  ``settings.artifacts / policy.json``.

Nothing in this package edits :mod:`app.cli.policy`; the shared code is
re-exported from :mod:`app.cli.policy` and consumed read-only.
"""

from app.policy.store import (
    ACTIVE_POLICY_FILENAME,
    PolicyStore,
    get_default_store,
)

__all__ = [
    "ACTIVE_POLICY_FILENAME",
    "PolicyStore",
    "get_default_store",
]
