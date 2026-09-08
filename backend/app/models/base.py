"""Shared Pydantic base model.

The specification defines Firestore documents and JSON payloads using
``camelCase`` field names (``filePath``, ``lineNumber``, ``artefactType``, …)
while Python code is idiomatically ``snake_case``.

Rather than maintaining two parallel vocabularies, every domain model derives
from :class:`BlindspotModel`, which:

* keeps ``snake_case`` attribute names in Python,
* emits ``camelCase`` keys when serialised with ``by_alias=True``,
* accepts *either* spelling on input (``populate_by_name=True``).

Use :func:`serialise` when writing to Firestore or returning JSON so the wire
format always matches the specification.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class BlindspotModel(BaseModel):
    """Base model for every Blindspot domain object."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
        use_enum_values=False,
        str_strip_whitespace=True,
    )

    def serialise(self, **kwargs: Any) -> dict[str, Any]:
        """Dump to a camelCase dict suitable for Firestore / JSON responses."""
        kwargs.setdefault("by_alias", True)
        kwargs.setdefault("mode", "json")
        kwargs.setdefault("exclude_none", False)
        return self.model_dump(**kwargs)
