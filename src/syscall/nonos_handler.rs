// Module-level attributes removed - no_std is set at crate level

//! Syscall handler registration.

/// Returns a function pointer to the core syscall entry.
#[inline(always)]
pub fn syscall_entry_ptr() -> extern "C" fn() {
    super::handle_interrupt
}

/// For portability, we return the entry pointer for the caller to wire up.

#[inline]
pub fn register_syscall_handler() -> extern "C" fn() {
    syscall_entry_ptr()
}
