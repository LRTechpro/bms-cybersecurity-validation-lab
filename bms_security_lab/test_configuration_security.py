from dataclasses import replace

from .configuration_model import BMSConfiguration
from .configuration_validator import ConfigurationValidator


def config(
    version: int = 1,
    capacity: float = 100.0,
    cell_count: int = 192,
    scale: float = 1.0,
    minimum_v: float = 2.5,
    maximum_v: float = 4.2,
) -> BMSConfiguration:
    return BMSConfiguration.create(
        configuration_id="BMS-CAL-A",
        version=version,
        hardware_profile="PACK-192S",
        battery_capacity_ah=capacity,
        cell_count=cell_count,
        current_sensor_scale=scale,
        minimum_cell_voltage_v=minimum_v,
        maximum_cell_voltage_v=maximum_v,
    )


def validator_for(*approved: BMSConfiguration) -> ConfigurationValidator:
    return ConfigurationValidator(
        approved_hashes_by_version={item.version: item.content_hash for item in approved},
        expected_hardware_profile="PACK-192S",
        expected_cell_count=192,
        expected_current_sensor_scale=1.0,
    )


def test_approved_configuration_and_hash_pass() -> None:
    approved = config()
    assert validator_for(approved).validate(approved).status == "PASS"


def test_capacity_changed_without_authorization_fails() -> None:
    approved = config()
    tampered = replace(approved, battery_capacity_ah=200.0)
    result = validator_for(approved).validate(tampered)
    assert result.status == "FAIL"
    assert any("hash" in reason.lower() for reason in result.reasons)


def test_cell_count_mismatch_fails() -> None:
    mismatched = config(cell_count=191)
    result = validator_for(mismatched).validate(mismatched)
    assert result.status == "FAIL"
    assert any("cell count" in reason.lower() for reason in result.reasons)


def test_current_sensor_scaling_change_fails() -> None:
    altered = config(scale=1.1)
    result = validator_for(altered).validate(altered)
    assert result.status == "FAIL"
    assert any("scaling" in reason.lower() for reason in result.reasons)


def test_inconsistent_threshold_relationship_fails() -> None:
    inconsistent = config(minimum_v=4.3, maximum_v=4.2)
    result = validator_for(inconsistent).validate(inconsistent)
    assert result.status == "FAIL"
    assert any("threshold" in reason.lower() for reason in result.reasons)


def test_authorized_version_upgrade_passes_and_creates_audit_event() -> None:
    previous = config(version=1)
    proposed = config(version=2, capacity=105.0)
    validator = validator_for(previous, proposed)
    result = validator.apply_authorized_upgrade(
        previous=previous,
        proposed=proposed,
        actor="service-engineer",
        timestamp_s=100.0,
    )
    assert result.status == "PASS"
    assert len(validator.audit_events) == 1
    event = validator.audit_events[0]
    assert event.actor == "service-engineer"
    assert event.previous_values["battery_capacity_ah"] == 100.0
    assert event.new_values["battery_capacity_ah"] == 105.0
