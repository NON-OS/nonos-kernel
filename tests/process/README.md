# Process Module Tests

## Location

`src/process/*/tests.rs`

## Coverage (42 tests)

### Process Lifecycle

- Creation
- Execution
- Termination
- Cleanup

Source: `src/process/exec/tests.rs`

### NOX (Distributed Processes)

- Process creation
- State transitions
- Migration flow
- Node filtering

Source: `src/process/nox/tests.rs`

### Scheduling

- Priority handling
- Time slicing
- CPU affinity

Source: `src/process/sched/tests.rs`

## Known Issues

Process tests require kernel time. Fails with overflow in test mode.

## Running

```bash
cargo test --lib --features std process::
```
