from .checkpoint_store import CheckpointStore
from .test_case import ValidationTestCase


class TestRunner:
    """Run tests independently so one ERROR cannot stop the campaign."""

    def __init__(
        self,
        test_cases: list[ValidationTestCase],
        checkpoint_store: CheckpointStore,
    ) -> None:
        self.test_cases = test_cases
        self.checkpoint_store = checkpoint_store
        self.errors: dict[str, str] = {}

    def run_all(self) -> list[tuple[str, str]]:
        results: list[tuple[str, str]] = []

        for test_case in self.test_cases:
            saved_status = self.checkpoint_store.get_status(test_case.test_id)

            if saved_status is not None:
                print(f"Resume: skipping {test_case.test_id}")
                results.append((test_case.test_id, saved_status))
                continue

            try:
                result = test_case.run()
                status = result.status
            except Exception as error:  # Campaign boundary intentionally broad.
                status = "ERROR"
                self.errors[test_case.test_id] = (
                    f"{type(error).__name__}: {error}"
                )

            self.checkpoint_store.mark_completed(
                test_case.test_id,
                status,
            )
            results.append((test_case.test_id, status))

        return results
