import json
from pathlib import Path


class CheckpointStore:
    def __init__(
        self,
        file_path: str = "bms_security_lab/evidence/checkpoint.json",
    ) -> None:
        self.file_path = Path(file_path)
        self.completed_results = self._load()

    def _load(self) -> dict[str, str]:
        if not self.file_path.exists():
            return {}

        with self.file_path.open("r", encoding="utf-8") as file:
            return json.load(file)

    def is_completed(self, test_id: str) -> bool:
        return test_id in self.completed_results

    def get_status(self, test_id: str) -> str | None:
        return self.completed_results.get(test_id)

    def mark_completed(
        self,
        test_id: str,
        status: str,
    ) -> None:
        self.completed_results[test_id] = status

        self.file_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self.file_path.open("w", encoding="utf-8") as file:
            json.dump(
                self.completed_results,
                file,
                indent=2,
                sort_keys=True,
            )