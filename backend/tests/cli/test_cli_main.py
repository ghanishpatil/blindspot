"""Integration tests for the ``blindspot-scan`` CLI entrypoint.

Instead of calling out to a subprocess (slow, environment-sensitive)
we invoke :func:`app.cli.main.main` directly with argv lists and mock
the actual pipeline call. That keeps these tests deterministic and
fast while still exercising the full argparse -> handler -> emit path.

Contract:

1. Exit codes match the SPEC: 0 / 1 / 2 / 3.
2. stdout is JSON only on the success path.
3. --out writes to a file, stdout stays empty.
4. --quiet suppresses stderr progress but does not touch stdout.
5. Invalid target path exits 1 (runtime), not 2 (policy) or 3 (usage).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.cli import main as cli_main


# ---------------------------------------------------------------------------
# A fake envelope returned by the mocked pipeline. Small and stable so
# assertions read cleanly.
# ---------------------------------------------------------------------------

_FAKE_ENVELOPE_BASE: dict[str, Any] = {
    "schemaVersion": "blindspot.scan.v1",
    "generatedAt": "2026-09-07T12:00:00+00:00",
    "cli": {"version": "0.1.0"},
    "pipeline": {"version": "0.1.0"},
    "target": {"path": "/fake", "gitRef": None, "gitBranch": None},
    "summary": {"totalFindings": 0},
    "findings": [],
}


def _finding(
    algorithm: str = "MD5",
    *,
    weak: bool = True,
    tier: str = "overdue",
    fid: str = "F1",
) -> dict[str, Any]:
    return {
        "id": fid,
        "algorithm": algorithm,
        "parameter": None,
        "curve": None,
        "filePath": "src/demo.py",
        "lineNumber": 10,
        "riskTier": tier,
        "isCurrentlyWeak": weak,
        "isQuantumSensitive": True,
        "isHndlExposed": False,
        "parameterStatus": "resolved",
        "needsVerification": False,
        "evidence": {
            "filePath": "src/demo.py",
            "lineNumber": 10,
            "ruleId": "rule-a",
            "detectionMethod": "semgrep_api_pattern",
        },
    }


@pytest.fixture
def stub_pipeline(monkeypatch: pytest.MonkeyPatch):
    """Replace ``build_scan_envelope`` inside the CLI's own namespace
    so the tests never run the real pipeline."""

    def _stub_factory(findings: list[dict[str, Any]] | None = None):
        env = dict(_FAKE_ENVELOPE_BASE)
        env["findings"] = list(findings or [])
        env["summary"] = {"totalFindings": len(env["findings"])}
        return env

    # Return a mutable slot the test can populate.
    holder: dict[str, list[dict[str, Any]]] = {"findings": []}

    def _stub_build(target, project_id="ci", settings=None, now=None):
        return _stub_factory(holder["findings"])

    monkeypatch.setattr(cli_main, "build_scan_envelope", _stub_build)
    return holder


@pytest.fixture
def target_dir(tmp_path: Path) -> Path:
    """A real directory the CLI can point at without hitting the pipeline."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "demo.py").write_text("x = 1\n", encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# scan subcommand
# ---------------------------------------------------------------------------

def test_scan_writes_json_to_stdout(
    stub_pipeline, target_dir: Path, capsys: pytest.CaptureFixture
) -> None:
    stub_pipeline["findings"] = [_finding()]
    exit_code = cli_main.main(["scan", str(target_dir)])
    assert exit_code == cli_main.EXIT_OK

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["schemaVersion"] == "blindspot.scan.v1"
    assert payload["findings"][0]["algorithm"] == "MD5"


def test_scan_out_flag_writes_file_and_leaves_stdout_empty(
    stub_pipeline, target_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out = tmp_path / "scan.json"
    exit_code = cli_main.main(["scan", str(target_dir), "--out", str(out)])
    assert exit_code == cli_main.EXIT_OK
    assert out.is_file()
    assert capsys.readouterr().out == ""
    assert json.loads(out.read_text())["schemaVersion"] == "blindspot.scan.v1"


def test_scan_bad_path_returns_runtime_error(
    stub_pipeline, tmp_path: Path
) -> None:
    exit_code = cli_main.main(["scan", str(tmp_path / "does-not-exist")])
    assert exit_code == cli_main.EXIT_ERROR


# ---------------------------------------------------------------------------
# diff subcommand
# ---------------------------------------------------------------------------

def test_diff_with_missing_baseline_treats_as_empty(
    stub_pipeline, target_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """A missing --baseline file must NOT crash the CLI. We treat it
    as an empty baseline so the first-ever scan of a project still
    produces useful output."""
    stub_pipeline["findings"] = [_finding()]
    exit_code = cli_main.main([
        "diff", str(target_dir),
        "--baseline", str(tmp_path / "nope.json"),
    ])
    assert exit_code == cli_main.EXIT_OK

    payload = json.loads(capsys.readouterr().out)
    assert payload["counts"]["introduced"] == 1


def test_diff_against_matching_baseline_reports_unchanged(
    stub_pipeline, target_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    baseline_env = dict(_FAKE_ENVELOPE_BASE)
    baseline_env["findings"] = [_finding()]
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline_env), encoding="utf-8")

    stub_pipeline["findings"] = [_finding()]
    exit_code = cli_main.main([
        "diff", str(target_dir), "--baseline", str(baseline_path),
    ])
    assert exit_code == cli_main.EXIT_OK

    payload = json.loads(capsys.readouterr().out)
    assert payload["counts"]["unchanged"] == 1
    assert payload["counts"]["introduced"] == 0


# ---------------------------------------------------------------------------
# gate subcommand -- the whole point of the CLI
# ---------------------------------------------------------------------------

def test_gate_clean_scan_returns_zero(
    stub_pipeline, target_dir: Path, tmp_path: Path
) -> None:
    baseline_env = dict(_FAKE_ENVELOPE_BASE)
    baseline_env["findings"] = []
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline_env), encoding="utf-8")

    stub_pipeline["findings"] = []
    exit_code = cli_main.main([
        "gate", str(target_dir), "--baseline", str(baseline_path),
    ])
    assert exit_code == cli_main.EXIT_OK


def test_gate_new_weak_finding_returns_two(
    stub_pipeline, target_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """The whole reason this CLI exists: introducing a currently-weak
    algorithm (MD5) must fail the build with exit code 2."""
    baseline_env = dict(_FAKE_ENVELOPE_BASE)
    baseline_env["findings"] = []
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline_env), encoding="utf-8")

    stub_pipeline["findings"] = [_finding(algorithm="MD5", weak=True)]
    exit_code = cli_main.main([
        "gate", str(target_dir), "--baseline", str(baseline_path),
    ])
    assert exit_code == cli_main.EXIT_POLICY_VIOLATION

    # The delta + policy payload still emits on stdout so CI can render
    # the reason. That's the SPEC contract.
    payload = json.loads(capsys.readouterr().out)
    assert payload["counts"]["introduced"] == 1
    assert "policy" in payload
    rule_ids = {v["ruleId"] for v in payload["policy"]["violations"]}
    assert "no-new-weak-now" in rule_ids


def test_gate_only_warn_violation_returns_zero(
    stub_pipeline, target_dir: Path, tmp_path: Path
) -> None:
    """A finding that trips only the ``warn-new-hndl`` rule must NOT
    fail the build -- warn is informational, not blocking."""
    baseline_env = dict(_FAKE_ENVELOPE_BASE)
    baseline_env["findings"] = []
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline_env), encoding="utf-8")

    hndl_only = _finding(algorithm="AES", weak=False, tier="low-risk")
    hndl_only["isHndlExposed"] = True
    stub_pipeline["findings"] = [hndl_only]
    exit_code = cli_main.main([
        "gate", str(target_dir), "--baseline", str(baseline_path),
    ])
    assert exit_code == cli_main.EXIT_OK


def test_gate_malformed_policy_returns_usage_error(
    stub_pipeline, target_dir: Path, tmp_path: Path
) -> None:
    """A policy typo must fail as EXIT_USAGE (3), not as a policy
    violation (2). CI operators need to distinguish 'your policy JSON
    is broken' from 'your PR violates policy'."""
    baseline_env = dict(_FAKE_ENVELOPE_BASE)
    baseline_env["findings"] = []
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline_env), encoding="utf-8")

    bad_policy = tmp_path / "policy.json"
    bad_policy.write_text('{ "rules": [{"id": "x", "on": "wrong-bucket", "match": {"x": 1}, "action": "block" }] }', encoding="utf-8")

    exit_code = cli_main.main([
        "gate", str(target_dir),
        "--baseline", str(baseline_path),
        "--policy", str(bad_policy),
    ])
    assert exit_code == cli_main.EXIT_USAGE


# ---------------------------------------------------------------------------
# General CLI plumbing
# ---------------------------------------------------------------------------

def test_no_subcommand_returns_usage_error() -> None:
    """``blindspot-scan`` with no subcommand must exit 3, not 1 or 2."""
    exit_code = cli_main.main([])
    assert exit_code == cli_main.EXIT_USAGE


def test_version_flag_returns_zero(capsys: pytest.CaptureFixture) -> None:
    exit_code = cli_main.main(["--version"])
    assert exit_code == cli_main.EXIT_OK
    assert "blindspot-scan" in capsys.readouterr().out


def test_bad_flag_returns_usage_error() -> None:
    """Unknown flag must exit 3 -- distinguishing usage bugs from
    real runtime failures."""
    exit_code = cli_main.main(["scan", "--nope"])
    assert exit_code == cli_main.EXIT_USAGE
