import argparse

from .campaign_builder import CampaignRunner, build_default_campaign


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the simulated BMS cybersecurity validation campaign."
    )
    parser.add_argument(
        "--output-dir",
        default="bms_security_lab/evidence/runs",
        help=(
            "Directory for runtime checkpoint, evidence, and reports. "
            "Defaults to a gitignored runs directory so the committed "
            "capstone evidence is never overwritten."
        ),
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=None,
        help="Execute only this many new cases to demonstrate interruption.",
    )
    parser.add_argument(
        "--code-version",
        default="development",
        help="Commit or release identifier bound to checkpoint and evidence.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    runner = CampaignRunner(
        cases=build_default_campaign(),
        output_dir=args.output_dir,
        code_version=args.code_version,
    )
    summary = runner.run(max_new_cases=args.max_cases)
    json_report, markdown_report = runner.write_reports(summary)

    print(f"Campaign: {summary.campaign_id}")
    print(f"Completed: {summary.completed_cases}/{summary.total_cases}")
    print(f"Newly executed: {summary.newly_executed}")
    print(f"Resumed: {summary.resumed_cases}")
    print(f"Expected outcomes matched: {summary.expected_matches}")
    print(f"Unexpected outcomes: {summary.unexpected_results}")
    print(f"Isolated ERROR cases: {summary.error_cases}")
    print(f"Closed findings: {summary.closed_findings}")
    print(f"Campaign digest: {summary.campaign_digest}")
    print(f"JSON evidence: {json_report}")
    print(f"Markdown report: {markdown_report}")

    complete = summary.completed_cases == summary.total_cases
    deterministic = summary.unexpected_results == 0
    findings_closed = summary.open_findings == 0
    return 0 if complete and deterministic and findings_closed else 1


if __name__ == "__main__":
    raise SystemExit(main())
