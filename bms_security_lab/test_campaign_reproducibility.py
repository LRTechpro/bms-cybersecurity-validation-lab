"""Regression tests for campaign resume, evidence integrity, and idempotency.

These cover the failure mode where a fresh clone contains a committed evidence
chain but no checkpoint because the checkpoint file is gitignored. The runner
must resume from recorded evidence instead of re-executing it, must not append
duplicate records, and must archive evidence from another code version.
"""

from pathlib import Path

from bms_security_lab.campaign_builder import (
    CampaignRunner,
    build_default_campaign,
)


def _run(output_dir: Path, code_version: str):
    runner = CampaignRunner(
        cases=build_default_campaign(),
        output_dir=output_dir,
        code_version=code_version,
    )
    return runner, runner.run()


def _seed_committed_chain(tmp_path: Path, code_version: str):
    """Produce evidence, then delete the checkpoint to mimic a fresh clone."""
    seed_dir = tmp_path / "seed"
    _, seed_summary = _run(seed_dir, code_version)
    (seed_dir / "checkpoint.json").unlink()
    return seed_dir, seed_summary


def test_fresh_clone_resumes_without_re_executing(tmp_path):
    """Evidence present, checkpoint absent, same build results in pure resume."""
    seed_dir, _ = _seed_committed_chain(tmp_path, "release-1")
    before = (seed_dir / "evidence.jsonl").read_text().splitlines()

    runner, summary = _run(seed_dir, "release-1")

    assert summary.newly_executed == 0
    assert summary.resumed_cases == summary.total_cases
    assert summary.completed_cases == summary.total_cases
    after = (seed_dir / "evidence.jsonl").read_text().splitlines()
    assert len(after) == len(before)
    assert runner.evidence_store.verify_chain()


def test_fresh_clone_does_not_crash_on_restored_finding(tmp_path):
    """Restoring a previously closed retest remains idempotent."""
    seed_dir, _ = _seed_committed_chain(tmp_path, "release-1")

    _, summary = _run(seed_dir, "release-1")

    assert summary.closed_findings == 1
    assert summary.open_findings == 0


def test_digest_is_reproducible_for_same_code_version(tmp_path):
    """A resumed run reports the original campaign digest."""
    seed_dir, seed_summary = _seed_committed_chain(tmp_path, "release-1")

    _, summary = _run(seed_dir, "release-1")

    assert summary.campaign_digest == seed_summary.campaign_digest


def test_different_code_version_archives_and_reruns(tmp_path):
    """Evidence from another build is archived before a clean rerun."""
    seed_dir, _ = _seed_committed_chain(tmp_path, "release-1")

    runner, summary = _run(seed_dir, "release-2")

    assert (seed_dir / "evidence.stale.jsonl").exists()
    assert summary.newly_executed == summary.total_cases
    assert summary.unexpected_results == 0
    assert summary.open_findings == 0
    assert runner.evidence_store.verify_chain()


def test_repeated_runs_are_idempotent(tmp_path):
    """Running twice in the same directory does not duplicate evidence."""
    run_dir = tmp_path / "run"
    _run(run_dir, "release-1")
    lines_first = (run_dir / "evidence.jsonl").read_text().splitlines()

    runner, summary = _run(run_dir, "release-1")
    lines_second = (run_dir / "evidence.jsonl").read_text().splitlines()

    assert summary.newly_executed == 0
    assert len(lines_first) == len(lines_second)
    assert runner.evidence_store.verify_chain()
