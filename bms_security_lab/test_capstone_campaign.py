import json
import shutil

from .campaign_builder import CampaignRunner, build_default_campaign
from .evidence_report import EvidenceStore
from .finding import FindingStatus


def run_complete(output_dir, code_version: str = "capstone-test"):
    runner = CampaignRunner(
        cases=build_default_campaign(),
        output_dir=output_dir,
        code_version=code_version,
    )
    summary = runner.run()
    return runner, summary


def test_clean_campaign_runs_more_than_fifty_unique_cases(tmp_path) -> None:
    cases = build_default_campaign()
    runner, summary = run_complete(tmp_path / "campaign")
    assert len(cases) >= 50
    assert len({case.test_id for case in cases}) == len(cases)
    assert summary.completed_cases == summary.total_cases == len(cases)
    assert summary.expected_matches == len(cases)
    assert summary.unexpected_results == 0
    assert runner.evidence_store.verify_chain() is True


def test_interrupted_campaign_resumes_after_saved_cases(tmp_path) -> None:
    output_dir = tmp_path / "resume"
    first = CampaignRunner(
        cases=build_default_campaign(),
        output_dir=output_dir,
        code_version="resume-test",
    )
    partial = first.run(max_new_cases=20)
    assert partial.completed_cases == 20
    assert partial.newly_executed == 20

    resumed = CampaignRunner(
        cases=build_default_campaign(),
        output_dir=output_dir,
        code_version="resume-test",
    )
    final = resumed.run()
    assert final.completed_cases == final.total_cases
    assert final.resumed_cases == 20
    assert final.newly_executed == final.total_cases - 20
    assert len(resumed.evidence_store.records) == final.total_cases


def test_one_executor_error_is_isolated_and_later_cases_continue(tmp_path) -> None:
    runner, summary = run_complete(tmp_path / "error")
    assert summary.error_cases == 1
    assert runner.checkpoint.completed["SAFE-004"] == "ERROR"
    assert runner.checkpoint.completed["RETEST-SENS-006"] == "PASS"
    assert summary.completed_cases == summary.total_cases


def test_designed_attack_creates_finding_and_evidence(tmp_path) -> None:
    runner, summary = run_complete(tmp_path / "finding")
    findings = runner.findings.all_findings()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.root_cause_key == "TRUSTED-STATE-GATE-BYPASS"
    assert finding.evidence_record_hashes
    evidence = next(
        record
        for record in runner.evidence_store.records
        if record.test_id == "SENS-006"
    )
    assert evidence.status == "FAIL"
    assert summary.closed_findings == 1


def test_remediated_case_closes_only_after_passing_retest(tmp_path) -> None:
    output_dir = tmp_path / "retest"
    cases = build_default_campaign()
    runner = CampaignRunner(cases, output_dir, code_version="retest-test")

    # Stop immediately after the vulnerable baseline case.
    vulnerable_index = next(
        index for index, case in enumerate(cases, start=1)
        if case.test_id == "SENS-006"
    )
    partial = runner.run(max_new_cases=vulnerable_index)
    finding = runner.findings.all_findings()[0]
    assert partial.open_findings == 1
    assert finding.status is FindingStatus.OPEN

    resumed = CampaignRunner(cases, output_dir, code_version="retest-test")
    final = resumed.run()
    restored_finding = resumed.findings.all_findings()[0]
    assert final.open_findings == 0
    assert restored_finding.status is FindingStatus.CLOSED
    assert restored_finding.remediation_id == "REM-CAPSTONE-001"
    assert restored_finding.retest_evidence_hash is not None


def test_repeated_clean_campaign_is_deterministic(tmp_path) -> None:
    output_dir = tmp_path / "deterministic"
    first_runner, first_summary = run_complete(output_dir, "deterministic-sha")
    first_records = [
        (record.test_id, record.status, record.record_hash)
        for record in first_runner.evidence_store.records
    ]
    first_digest = first_summary.campaign_digest

    shutil.rmtree(output_dir)
    second_runner, second_summary = run_complete(
        output_dir,
        "deterministic-sha",
    )
    second_records = [
        (record.test_id, record.status, record.record_hash)
        for record in second_runner.evidence_store.records
    ]
    assert second_summary.campaign_digest == first_digest
    assert second_records == first_records


def test_reports_include_digest_traceability_and_residual_risk(tmp_path) -> None:
    runner, summary = run_complete(tmp_path / "reports")
    json_path, markdown_path = runner.write_reports(summary)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = markdown_path.read_text(encoding="utf-8")
    assert payload["campaign_digest"] == summary.campaign_digest
    assert payload["record_count"] == summary.total_cases
    assert "TARA-001" in json_path.read_text(encoding="utf-8")
    assert summary.campaign_digest in markdown
    assert "Residual-risk decision" in markdown
    assert "CLOSED" in markdown


def test_code_version_change_marks_prior_checkpoint_stale(tmp_path) -> None:
    output_dir = tmp_path / "stale"
    first = CampaignRunner(
        build_default_campaign(),
        output_dir,
        code_version="version-a",
    )
    first.run(max_new_cases=5)

    changed = CampaignRunner(
        build_default_campaign(),
        output_dir,
        code_version="version-b",
    )
    assert changed.checkpoint.completed == {}
    assert (output_dir / "evidence.stale.jsonl").exists()
    rerun = changed.run(max_new_cases=1)
    assert rerun.newly_executed == 1
    assert EvidenceStore(output_dir / "evidence.jsonl").verify_chain() is True
