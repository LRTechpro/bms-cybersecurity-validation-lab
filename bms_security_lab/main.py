from .checkpoint_store import CheckpointStore
from .test_runner import TestRunner
from .test_case import ValidationTestCase
from .trusted_state import TrustedBMSState
from .sensor_reading import BatterySensorReading
from .validator import AuthenticationValidator, BMSValidator

state = TrustedBMSState()

print(f"Initial trusted SOC: {state.get_soc()}%")

state.update_soc(75.0)

print(f"Updated trusted SOC: {state.get_soc()}%")

try:
    state.update_soc(145.0)
except ValueError as error:
    print(f"Rejected update: {error}")

print(f"Final trusted SOC: {state.get_soc()}%")

reading = BatterySensorReading(
    soc_percent=82.0,
    pack_voltage_v=720.0,
    pack_current_a=40.0,
    max_temperature_c=35.0,
    source_id=0x180,
    sequence_counter=1,
    authenticated=True,
)

test_cases = [
    ValidationTestCase(
        test_id="TEST-RANGE-001",
        reading=reading,
        validator=BMSValidator(),
    ),
    ValidationTestCase(
        test_id="TEST-AUTH-001",
        reading=reading,
        validator=AuthenticationValidator(),
    ),
]

checkpoint_store = CheckpointStore()

runner = TestRunner(
    test_cases,
    checkpoint_store,
)

results = runner.run_all()

all_passed = True

for test_id, status in results:
    print(f"{test_id}: {status}")

    if status != "PASS":
        all_passed = False

if all_passed:
    state.update_soc(reading.soc_percent)

print(f"Trusted SOC after validation: {state.get_soc()}%")


