import csv
import shutil

from .artifact_validator import DOCS_DIR, validate_engineering_artifacts


def test_engineering_artifacts_have_valid_end_to_end_traceability() -> None:
    report = validate_engineering_artifacts()
    assert report.errors == ()
    assert report.counts == {
        "assets": 10,
        "tara_records": 9,
        "cybersecurity_goals": 9,
        "architecture_controls": 10,
        "security_requirements": 31,
        "traceability_rows": 9,
        "campaign_cases": 54,
    }


def test_unknown_requirement_reference_fails_artifact_gate(tmp_path) -> None:
    docs_copy = tmp_path / "docs"
    shutil.copytree(DOCS_DIR, docs_copy)
    path = docs_copy / "traceability_matrix.csv"
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
        fieldnames = list(rows[0])
    rows[0]["requirement_ids"] += "; BMS-SEC-UNKNOWN-999"
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    report = validate_engineering_artifacts(docs_copy)

    assert report.passed is False
    assert any("BMS-SEC-UNKNOWN-999" in error for error in report.errors)
