import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class EvidenceRecord:
    """Traceable test evidence with a previous-record hash link."""

    campaign_id: str
    test_id: str
    tara_id: str
    cybersecurity_goal_id: str
    requirement_id: str
    architecture_control_ids: tuple[str, ...]
    input_data: dict[str, Any]
    preconditions: dict[str, Any]
    expected_result: str
    observed_result: str
    status: str
    reasons: tuple[str, ...]
    timestamp_s: float
    environment: str
    code_version: str
    evidence_paths: tuple[str, ...] = ()
    previous_record_hash: str = "GENESIS"
    record_hash: str = field(default="", compare=True)

    def canonical_payload(self) -> bytes:
        data = asdict(self)
        data.pop("record_hash", None)
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

    def computed_hash(self) -> str:
        return hashlib.sha256(self.canonical_payload()).hexdigest()

    def with_hash(self) -> "EvidenceRecord":
        data = asdict(self)
        data["record_hash"] = self.computed_hash()
        data["architecture_control_ids"] = tuple(
            data["architecture_control_ids"]
        )
        data["reasons"] = tuple(data["reasons"])
        data["evidence_paths"] = tuple(data["evidence_paths"])
        return EvidenceRecord(**data)


class EvidenceStore:
    """Persist and reload a tamper-evident JSONL evidence chain."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.records: list[EvidenceRecord] = []
        if self.path.exists():
            self._load()

    def append(self, record: EvidenceRecord) -> EvidenceRecord:
        previous_hash = (
            self.records[-1].record_hash if self.records else "GENESIS"
        )
        data = asdict(record)
        data["previous_record_hash"] = previous_hash
        data["record_hash"] = ""
        data["architecture_control_ids"] = tuple(
            data["architecture_control_ids"]
        )
        data["reasons"] = tuple(data["reasons"])
        data["evidence_paths"] = tuple(data["evidence_paths"])
        stored = EvidenceRecord(**data).with_hash()
        self.records.append(stored)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(asdict(stored), sort_keys=True) + "\n")
        return stored

    def verify_chain(self) -> bool:
        expected_previous = "GENESIS"
        for record in self.records:
            if record.previous_record_hash != expected_previous:
                return False
            if record.record_hash != record.computed_hash():
                return False
            expected_previous = record.record_hash
        return True

    def campaign_digest(self) -> str:
        joined_hashes = "".join(record.record_hash for record in self.records)
        return hashlib.sha256(joined_hashes.encode("ascii")).hexdigest()

    def _load(self) -> None:
        self.records.clear()
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            data = json.loads(line)
            data["architecture_control_ids"] = tuple(
                data["architecture_control_ids"]
            )
            data["reasons"] = tuple(data["reasons"])
            data["evidence_paths"] = tuple(data["evidence_paths"])
            self.records.append(EvidenceRecord(**data))
        if not self.verify_chain():
            raise ValueError("Evidence hash chain verification failed.")


class EvidenceReportBuilder:
    """Generate machine-readable and human-readable campaign reports."""

    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def write_json(self, path: str | Path) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "campaign_digest": self.store.campaign_digest(),
            "record_count": len(self.store.records),
            "records": [asdict(record) for record in self.store.records],
        }
        output.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return output

    def write_markdown(self, path: str | Path) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# BMS Cybersecurity Validation Evidence Report",
            "",
            f"Campaign digest: `{self.store.campaign_digest()}`",
            f"Evidence records: {len(self.store.records)}",
            "",
            "| Test | TARA | Requirement | Status | Observation |",
            "|---|---|---|---|---|",
        ]
        for record in self.store.records:
            lines.append(
                f"| {record.test_id} | {record.tara_id} | "
                f"{record.requirement_id} | {record.status} | "
                f"{record.observed_result.replace('|', '/')} |"
            )
        output.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return output
