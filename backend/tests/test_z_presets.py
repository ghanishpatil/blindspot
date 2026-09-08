"""Z preset tests.

DEMO_REQUIREMENTS §4.4 requires at least one alternate Z source. The India CII
and NIST IR 8547 timelines are named regulatory deadlines, not assumptions —
showing findings shift tiers under different Z values is a strong demo beat.
"""

from __future__ import annotations

from app.config import Settings


def test_z_presets_include_regulatory_timelines() -> None:
    settings = Settings()
    presets = settings.z_presets

    names = {p["name"] for p in presets}

    # At minimum: the demo default, India CII, NIST IR 8547, and a CRQC estimate.
    assert "Demo default" in names
    assert any("India CII" in n for n in names), "missing India CII timelines"
    assert any("NIST IR 8547" in n for n in names), "missing NIST IR 8547 timelines"
    assert any("CRQC" in n for n in names), "missing CRQC estimate"


def test_every_z_preset_carries_its_source() -> None:
    settings = Settings()
    for preset in settings.z_presets:
        assert preset["source"], f"Z preset {preset['name']!r} has no provenance"
        assert preset["z"] > 0, f"Z preset {preset['name']!r} has non-positive Z"
        assert preset["targetYear"] >= 2026


def test_z_presets_track_configured_z() -> None:
    """The first preset must reflect the active Z, not a hardcoded value."""
    settings = Settings(quantum_horizon_years=7, quantum_horizon_source="Custom test")
    default = settings.z_presets[0]

    assert default["z"] == 7
    assert default["source"] == "Custom test"


def test_preset_count_is_at_least_four() -> None:
    """Demo default + India CII + NIST + CRQC = at least 4 distinct Z values."""
    assert len(Settings().z_presets) >= 4
