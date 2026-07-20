from .checkpoint_store import CheckpointStore
from .test_case import ValidationTestCase


class TestRunner:
    def __init__(
        self,
        test_cases: list[ValidationTestCase],
        checkpoint_store: CheckpointStore,
    ) -> None:
        self.test_cases = test_cases
        self.checkpoint_store = checkpoint_store

    def run_all(self) -> list[tuple[str, str]]:
        results = []

        for test_case in self.test_cases:
            saved_status = self.checkpoint_store.get_status(
                test_case.test_id
            )

            if saved_status is not None:
                print(f"Resume: skipping {test_case.test_id}")
                results.append(
                    (test_case.test_id, saved_status)
                )
                continue

            result = test_case.run()

            self.checkpoint_store.mark_completed(
                test_case.test_id,
                result.status,
            )

            results.append(
                (test_case.test_id, result.status)
            )

        return results