"""Migration planning stage.

Consumes classified, risk-assessed, recommended findings and produces the
prioritized, costed :class:`~app.models.roadmap.MigrationRoadmap`. This is a
pure, deterministic transformation over data the pipeline already produced —
no scanning, no risk logic of its own.
"""
