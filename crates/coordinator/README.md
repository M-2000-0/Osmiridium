# osmiridium-coordinator

Session lifecycle, policy enforcement, and audit logging.

- **Session:** `SessionManager` states `Created→Configured→Running→Completed/Failed/Cancelled`; participants, circuit, `result: Option<Vec<Scalar>>`, timestamps.
- **Policy:** `SessionPolicy` / `PolicyEngine` checks `max_participants`, role access.
- **Audit:** `AuditLog` Blake3 hash-chained entries, tamper-evidence, per-session filtering.
- **Execution:** `execute()` (single-process SPDZ) and `execute_distributed()` (real TCP via `run_distributed`).

```rust
use osmiridium_coordinator::{Coordinator, SessionPolicy};
use osmiridium_protocol::ArithmeticCircuit;

let mut coord = Coordinator::new();
let id = coord.create_session("demo".into(), ArithmeticCircuit::new(), SessionPolicy::new(3, "test".into())).unwrap();
```

License: BUSL-1.1.
