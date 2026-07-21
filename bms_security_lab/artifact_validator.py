"""Cross-file integrity checks for the BMS engineering baseline."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .campaign_builder import CampaignCase, build_default_campaign


DOCS_DIR = Path(__file__).with_name("docs")


@dataclass(frozen=True)
class ArtifactValidationReport:
    """Result of validating the engineering artifacts and campaign links."""

    counts: dict[str, int]
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.errors


def _load_csv(
    docs_dir: Path,
    filename: str,
    primary_key: str,
    required_columns: set[str],
) -> tuple[list[dict[str, str]], list[str]]:
    path = docs_dir / filename
    errors: list[str] = []
    if not path.exists():
        return [], [f"Missing required artifact: {filename}"]

    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        columns = set(reader.fieldnames or ())
        missing_columns = required_columns - columns
        if missing_columns:
            errors.append(
                f"{filename} is missing columns: {', '.join(sorted(missing_columns))}"
            )
        rows = list(reader)

    identifiers = [row.get(primary_key, "").strip() for row in rows]
    blank_count = identifiers.count("")
    if blank_count:
        errors.append(f"{filename} contains {blank_count} blank {primary_key} value(s).")
    duplicates = sorted(
        identifier
        for identifier in set(identifiers)
        if identifier and identifiers.count(identifier) > 1
    )
    if duplicates:
        errors.append(
            f"{filename} contains duplicate {primary_key} values: "
            f"{', '.join(duplicates)}"
        )
    if not rows:
        errors.append(f"{filename} contains no records.")
    return rows, errors


def _split_ids(value: str) -> set[str]:
    return {item.strip() for item in value.split(";") if item.strip()}


def _check_references(
    rows: Iterable[dict[str, str]],
    row_id_field: str,
    reference_field: str,
    known_ids: set[str],
    artifact_name: str,
) -> list[str]:
    errors: list[str] = []
    for row in rows:
        row_id = row.get(row_id_field, "<unknown>")
        references = _split_ids(row.get(reference_field, ""))
        if not references:
            errors.append(
                f"{artifact_name} {row_id} has no {reference_field} reference."
            )
            continue
        unknown = sorted(references - known_ids)
        if unknown:
            errors.append(
                f"{artifact_name} {row_id} references unknown {reference_field}: "
                f"{', '.join(unknown)}"
            )
    return errors


def validate_engineering_artifacts(
    docs_dir: str | Path = DOCS_DIR,
    campaign_cases: Iterable[CampaignCase] | None = None,
) -> ArtifactValidationReport:
    """Verify IDs, cross-file links, traceability, and campaign references."""
    directory = Path(docs_dir)
    errors: list[str] = []

    assets, load_errors = _load_csv(
        directory,
        "asset_inventory.csv",
        "asset_id",
        {"asset_id", "asset_name", "security_properties", "damage_context"},
    )
    errors.extend(load_errors)
    tara, load_errors = _load_csv(
        directory,
        "tara_register.csv",
        "tara_id",
        {
            "tara_id",
            "asset_ids",
            "threat_scenario_and_attack_paths",
            "priority",
            "cybersecurity_goal_id",
            "status",
        },
    )
    errors.extend(load_errors)
    goals, load_errors = _load_csv(
        directory,
        "cybersecurity_goals.csv",
        "goal_id",
        {"goal_id", "cybersecurity_goal", "source_tara_ids", "status"},
    )
    errors.extend(load_errors)
    controls, load_errors = _load_csv(
        directory,
        "architecture_controls.csv",
        "control_id",
        {"control_id", "allocation", "responsibility_and_design_rationale", "status"},
    )
    errors.extend(load_errors)
    requirements, load_errors = _load_csv(
        directory,
        "security_requirements.csv",
        "requirement_id",
        {
            "requirement_id",
            "source_tara_ids",
            "source_goal_ids",
            "technical_security_requirement",
            "allocated_control_ids",
            "verification_method",
            "linked_test_ids",
            "status",
        },
    )
    errors.extend(load_errors)
    traceability, load_errors = _load_csv(
        directory,
        "traceability_matrix.csv",
        "tara_id",
        {
            "tara_id",
            "cybersecurity_goal_id",
            "requirement_ids",
            "architecture_control_ids",
            "validation_coverage",
            "required_evidence_outcome",
            "status",
        },
    )
    errors.extend(load_errors)

    asset_ids = {row["asset_id"] for row in assets if row.get("asset_id")}
    tara_ids = {row["tara_id"] for row in tara if row.get("tara_id")}
    goal_ids = {row["goal_id"] for row in goals if row.get("goal_id")}
    control_ids = {
        row["control_id"] for row in controls if row.get("control_id")
    }
    requirement_ids = {
        row["requirement_id"]
        for row in requirements
        if row.get("requirement_id")
    }
    requirement_by_id = {
        row["requirement_id"]: row
        for row in requirements
        if row.get("requirement_id")
    }

    errors.extend(
        _check_references(tara, "tara_id", "asset_ids", asset_ids, "TARA")
    )
    errors.extend(
        _check_references(
            tara,
            "tara_id",
            "cybersecurity_goal_id",
            goal_ids,
            "TARA",
        )
    )
    errors.extend(
        _check_references(
            goals,
            "goal_id",
            "source_tara_ids",
            tara_ids,
            "Cybersecurity goal",
        )
    )
    for field, known_ids in (
        ("source_tara_ids", tara_ids),
        ("source_goal_ids", goal_ids),
        ("allocated_control_ids", control_ids),
    ):
        errors.extend(
            _check_references(
                requirements,
                "requirement_id",
                field,
                known_ids,
                "Security requirement",
            )
        )
    for field, known_ids in (
        ("tara_id", tara_ids),
        ("cybersecurity_goal_id", goal_ids),
        ("requirement_ids", requirement_ids),
        ("architecture_control_ids", control_ids),
    ):
        errors.extend(
            _check_references(
                traceability,
                "tara_id",
                field,
                known_ids,
                "Traceability row",
            )
        )

    traced_requirements = set().union(
        *(
            _split_ids(row.get("requirement_ids", ""))
            for row in traceability
        ),
        set(),
    )
    untraced = sorted(requirement_ids - traced_requirements)
    if untraced:
        errors.append(
            "Requirements missing from the traceability matrix: "
            + ", ".join(untraced)
        )

    for row in traceability:
        row_tara = row.get("tara_id", "")
        row_goal = row.get("cybersecurity_goal_id", "")
        row_controls = _split_ids(row.get("architecture_control_ids", ""))
        for requirement_id in _split_ids(row.get("requirement_ids", "")):
            requirement = requirement_by_id.get(requirement_id)
            if requirement is None:
                continue
            if row_tara not in _split_ids(requirement["source_tara_ids"]):
                errors.append(
                    f"Traceability row {row_tara} includes {requirement_id}, "
                    "but the requirement does not identify that source TARA."
                )
            if row_goal not in _split_ids(requirement["source_goal_ids"]):
                errors.append(
                    f"Traceability row {row_tara} includes {requirement_id}, "
                    "but the requirement does not identify that source goal."
                )
            missing_controls = (
                _split_ids(requirement["allocated_control_ids"]) - row_controls
            )
            if missing_controls:
                errors.append(
                    f"Traceability row {row_tara} omits controls allocated to "
                    f"{requirement_id}: {', '.join(sorted(missing_controls))}"
                )

    cases = list(campaign_cases or build_default_campaign())
    case_ids = [case.test_id for case in cases]
    duplicate_cases = sorted(
        case_id for case_id in set(case_ids) if case_ids.count(case_id) > 1
    )
    if duplicate_cases:
        errors.append("Duplicate campaign test IDs: " + ", ".join(duplicate_cases))
    for case in cases:
        references = {
            "TARA": ({case.tara_id}, tara_ids),
            "goal": ({case.cybersecurity_goal_id}, goal_ids),
            "requirement": ({case.requirement_id}, requirement_ids),
            "control": (set(case.architecture_control_ids), control_ids),
        }
        for label, (values, known_ids) in references.items():
            unknown = sorted(values - known_ids)
            if unknown:
                errors.append(
                    f"Campaign case {case.test_id} references unknown {label}: "
                    f"{', '.join(unknown)}"
                )
        requirement = requirement_by_id.get(case.requirement_id)
        if requirement is None:
            continue
        if case.tara_id not in _split_ids(requirement["source_tara_ids"]):
            errors.append(
                f"Campaign case {case.test_id} maps to {case.requirement_id}, "
                "but that requirement has a different source TARA."
            )
        if case.cybersecurity_goal_id not in _split_ids(
            requirement["source_goal_ids"]
        ):
            errors.append(
                f"Campaign case {case.test_id} maps to {case.requirement_id}, "
                "but that requirement has a different source goal."
            )
        unallocated_controls = set(case.architecture_control_ids) - _split_ids(
            requirement["allocated_control_ids"]
        )
        if unallocated_controls:
            errors.append(
                f"Campaign case {case.test_id} references controls not allocated "
                f"to {case.requirement_id}: "
                f"{', '.join(sorted(unallocated_controls))}"
            )

    return ArtifactValidationReport(
        counts={
            "assets": len(assets),
            "tara_records": len(tara),
            "cybersecurity_goals": len(goals),
            "architecture_controls": len(controls),
            "security_requirements": len(requirements),
            "traceability_rows": len(traceability),
            "campaign_cases": len(cases),
        },
        errors=tuple(errors),
    )


def main() -> int:
    report = validate_engineering_artifacts()
    status = "PASS" if report.passed else "FAIL"
    print(f"ENGINEERING ARTIFACT INTEGRITY: {status}")
    for name, count in report.counts.items():
        print(f"{name}: {count}")
    for error in report.errors:
        print(f"ERROR: {error}")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
