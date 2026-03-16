# IPC Module Tests

## Location

`src/ipc/*/tests.rs`

## Coverage (51 tests)

### Channels

- Channel creation
- Message passing
- Blocking/non-blocking
- Capacity limits

Source: `src/ipc/nonos_channel/*/tests.rs`

### Messages

- Envelope construction
- Serialization
- ACK handling
- Validation

Source: `src/ipc/nonos_message/*/tests.rs`

### Policy Engine

- Rate limiting
- Permission checks
- Quota enforcement

Source: `src/ipc/nonos_policy/engine/tests.rs`

### Transport

- Stream management
- Frame handling
- MTU clamping
- ID uniqueness

Source: `src/ipc/nonos_transport/stream/tests.rs`

## Known Issues

Some IPC tests require kernel time functions. These fail in userspace test mode:

```
attempt to multiply with overflow
src/arch/x86_64/time/timer/time.rs:30
```

Fix: Mock time source for test builds.

## Running

```bash
cargo test --lib --features std ipc::
```
