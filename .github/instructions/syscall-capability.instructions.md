---
applyTo: "src/syscall/**,src/capabilities/**,abi/**"
---

# Syscall & Capability System — NONOS Kernel

## ABI-First Development

The ABI files in `abi/` are the **source of truth**. Code implements contracts, not the other way around.

| File | Defines |
|------|---------|
| `abi/syscalls.toml` | Syscall numbers, arg types, required capabilities, error codes |
| `abi/caps.toml` | Capability bits, groups, token format, MAC algorithm |
| `abi/wire.toml` | Register conventions, endianness, alignment |

**When adding a syscall:** update `abi/syscalls.toml` FIRST, then implement. Never add a syscall without an ABI entry.

## Syscall Dispatch

Location: `src/syscall/` (11 modules)

```
syscall/
├── mod.rs          # dispatch table, handle_syscall_dispatch()
├── types.rs        # SyscallNumber enum, arg structs
├── error.rs        # SyscallError enum
├── validate.rs     # argument validation
├── handlers/       # per-category syscall handlers
└── vdso.rs         # virtual dynamic shared object
```

### Adding a New Syscall

1. **Define in ABI** — add entry to `abi/syscalls.toml`:
   ```toml
   [syscalls.my_new_syscall]
   number = 42
   args = ["u64", "u64", "*const u8"]
   returns = "i64"
   required_capabilities = ["IO", "Memory"]
   error_codes = { EPERM = 1, EINVAL = 22, EFAULT = 14 }
   ```

2. **Add to dispatch** — register in `handle_syscall_dispatch()`:
   ```rust
   SyscallNumber::MyNewSyscall => {
       validate_args(arg0, arg1, arg2)?;
       check_capability(current_caps(), Capability::IO)?;
       check_capability(current_caps(), Capability::Memory)?;
       handle_my_new_syscall(arg0, arg1, arg2)
   }
   ```

3. **Validate arguments** — all syscall args are untrusted user input:
   ```rust
   fn handle_my_new_syscall(addr: u64, size: u64, buf_ptr: u64) -> Result<i64, SyscallError> {
       // Validate pointer is in user space, not kernel space
       validate_user_pointer(buf_ptr, size)?;
       // Validate address range doesn't overflow
       validate_address_range(addr, size)?;
       // ... implementation
   }
   ```

4. **Implement handler** in `syscall/handlers/`
5. **Add tests** with `#[cfg(test)]`

## Capability System

### 10 Capabilities

```rust
pub enum Capability {
    CoreExec,    // 0x001 — Execute capsules
    IO,          // 0x002 — Port I/O, MMIO
    Network,     // 0x004 — Network stack access
    IPC,         // 0x008 — Inter-process communication
    Memory,      // 0x010 — Memory management ops
    Crypto,      // 0x020 — Crypto primitives
    FileSystem,  // 0x040 — Filesystem access
    Hardware,    // 0x080 — Direct hardware control
    Debug,       // 0x100 — Debug/diagnostic operations
    Admin,       // 0x200 — System administration
}
```

Stored as `u64` bitmask — each capability is a power-of-2 bit.

### CapabilityToken Structure

```rust
pub struct CapabilityToken {
    pub owner_module: u64,
    pub permissions: Vec<Capability>,
    pub expires_at_ms: Option<u64>,
    pub nonce: u64,
    pub signature: [u8; 64],  // Ed25519 signature
}
```

### Role Presets (`capabilities/roles.rs`)

| Role | Capabilities | Use Case |
|------|-------------|----------|
| `KERNEL` | All | Kernel-internal operations |
| `SYSTEM_SERVICE` | CoreExec, IO, Network, IPC, Memory, Crypto, FileSystem | System daemons |
| `USER_APP` | CoreExec, IPC, Memory | Normal user applications |
| `NETWORK_SERVICE` | CoreExec, Network, IPC, Crypto | Network daemons |

### Capability Checking

**All checks must be constant-time** (via `subtle` crate):

```rust
use subtle::ConstantTimeEq;

pub fn check_capability(token: &CapabilityToken, required: Capability) -> Result<(), CapError> {
    // Verify signature first (constant-time)
    if !verify_token_signature(token)?.into() {
        return Err(CapError::InvalidSignature);
    }

    // Check expiration
    if let Some(expires) = token.expires_at_ms {
        if current_time_ms() > expires {
            return Err(CapError::Expired);
        }
    }

    // Check permission bit (constant-time)
    let has_cap = token.permission_bits() & (required as u64);
    let expected = required as u64;
    if has_cap.ct_eq(&expected).into() {
        Ok(())
    } else {
        Err(CapError::InsufficientCapability)
    }
}
```

### Capability Stack

```
Token → Chain → Delegation → MultiSig → Resource Quotas
```

- **Chain:** linked list of tokens for proving delegation path
- **Delegation:** token A grants a subset of its permissions to token B
- **MultiSig:** requires N-of-M token holders to authorize
- **Quotas:** rate/resource limits per capability

### Audit Trail

Every capability check is logged via `capabilities/audit/`:

```rust
audit_capability_check(token.owner_module, required_cap, granted);
```

## Syscall Argument Validation

ALL syscall arguments are **untrusted user input**:

```rust
// ✅ CORRECT — validate everything
fn sys_read(fd: u64, buf_ptr: u64, count: u64) -> Result<i64, SyscallError> {
    let fd = validate_fd(fd)?;                      // FD exists and is open
    validate_user_pointer(buf_ptr, count)?;           // Pointer in user space
    validate_buffer_size(count, MAX_READ_SIZE)?;      // Reasonable size
    check_capability(current_caps(), Capability::IO)?; // Has permission
    // ... now safe to proceed
}

// ❌ WRONG — trust user input
fn sys_read(fd: u64, buf_ptr: u64, count: u64) -> Result<i64, SyscallError> {
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, count as usize) };
    // Kernel crash if pointer is in kernel space or unmapped
}
```

## Anti-Patterns

- **No syscall without ABI entry** — update `abi/syscalls.toml` first
- **No trusting user pointers** — validate with `validate_user_pointer()`
- **No `==` on capability tokens** — use `ct_eq()` for constant-time comparison
- **No capability escalation** — delegated token can only have equal or fewer permissions
- **No expired token acceptance** — always check `expires_at_ms`
- **No silent capability failures** — every check must be audited
