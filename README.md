# BMS Cybersecurity Validation Engineering Lab

A pure-Python, simulation-only validation framework that converts BMS cybersecurity risks into traceable requirements, specialized controls, automated tests, evidence, findings, remediation, and retest closure.

## Project boundary

This repository demonstrates hands-on project experience with BMS TARA, cybersecurity architecture, technical security requirements, validation design, and evidence generation. It does not claim OEM production ownership, certified compliance, production key management, or authorization to test live vehicles, energized battery systems, operational BESS sites, or third-party devices.

## Architecture

```text
TARA / goals / requirements / controls
                  |
                  v
       Risk-driven campaign builder
                  |
       +----------+-----------+
       |          |           |
       v          v           v
 Sensor trust   Commands   Software/OT trust
 range/rate     state      config/firmware/network
 cross-signal   auth       signature/hash/roles
 replay/source  freshness  zones/ranges/recovery
       |          |           |
       +----------+-----------+
                  |
                  v
       PASS / FAIL / ERROR decision
                  |
       +----------+-----------+
       |                      |
       v                      v
 Mode-aware safe state   Security events
 and controlled recovery and anomaly correlation
       |                      |
       +----------+-----------+
                  |
                  v
      Hash-chained evidence records
                  |
                  v
 Finding -> remediation -> passing retest -> closure
                  |
                  v
     JSON evidence + Markdown report + digest
```

## Completed scope

- Foundation Gate: system definition, 10 assets, 9 TARA records, goals, 31 security requirements, architecture controls, and traceability
- Phases 0–8: OOP foundation and sensor security
- Phases 9–11: CAN/CAN-FD parsing, structured fuzzing, timing, flooding, and bounded resources
- Phases 12–14: command state machine, diagnostic security, and configuration integrity
- Phase 15: Ed25519 secure-boot/update prototype with SHA-256 image integrity, key lifecycle, anti-rollback, verify-to-activate, and recovery
- Phase 16: local mock Modbus/OT identity, role, zone, function, range, and rate policy
- Phases 17–19: events, correlation, safe state, recovery, hash-chained evidence, findings, remediation, and retest
- Phase 20: 54-case capstone campaign with resume, one isolated ERROR, deterministic replay, reporting, and residual-risk decision

## Install and test

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

## Run the complete capstone

```powershell
python -m bms_security_lab.main --code-version local-build
```

Runtime output is written to a gitignored `bms_security_lab/evidence/runs/` directory so the committed capstone evidence is never overwritten:

```text
checkpoint.json
campaign_evidence.json
evidence.jsonl
campaign_report.md
```

The released capstone evidence under `bms_security_lab/evidence/capstone/` is the preserved v1.0.0 reference record. To reproduce and re-verify it in place, point the runner at that directory with the matching code version:

```powershell
python -m bms_security_lab.main --output-dir bms_security_lab/evidence/capstone --code-version f547b6e
```

The run resumes the recorded chain, re-executes nothing, and reports the same campaign digest. A different code version archives the prior chain to `evidence.stale.jsonl` and starts a fresh run rather than modifying the released evidence.

## Demonstrate interruption and resume

Run only 20 new cases:

```powershell
python -m bms_security_lab.main --max-cases 20 --code-version local-build
```

Run the same command without `--max-cases` to resume the remaining cases in the same runs directory:

```powershell
python -m bms_security_lab.main --code-version local-build
```

The checkpoint is bound to the campaign definition and code version. A changed code version marks prior progress stale and forces re-execution rather than silently reusing obsolete results.

## Design responsibilities

| Component | Responsibility |
|---|---|
| Domain models | Immutable readings, frames, commands, configurations, firmware packages, requests, and events |
| Specialized validators | One security concern per class with specific reasons |
| Trusted-state boundary | Prevent unvalidated data from becoming trusted state |
| Campaign builder | Dependency injection, ordered execution, interruption, resume, and exception isolation |
| Safe-state controller | Select deterministic actions by failure class and operating mode |
| Evidence store | Persist complete records with SHA-256 hash chaining and campaign digest |
| Finding workflow | Deduplicate root causes and require a passing retest before closure |

## Architecture and Design Rationale

> I designed the project as layers instead of one large script. Immutable domain objects carry the exact input. Specialized validators evaluate one security responsibility at a time. The control decision stays separate from execution, so a validator cannot directly change trusted BMS state or execute a command. A campaign runner injects the test cases, isolates exceptions, checkpoints progress, and creates traceable evidence. Failures can produce structured security events, mode-aware safe-state actions, and findings. A finding remains open after remediation and closes only when a new linked retest passes. This structure lets me add another threat or validator without rewriting the complete framework.

## Security notes

- Ed25519 verifies signatures over the exact stored manifest bytes.
- SHA-256 verifies the firmware image digest carried in the manifest.
- Disposable private signing keys are generated only in tests and are never stored in runtime modules.
- Application CRC is treated as error detection, not cryptographic authentication.
- All CAN, diagnostic, Modbus, firmware, flooding, and recovery behavior remains local simulation only.
