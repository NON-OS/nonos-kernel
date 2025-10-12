/// Syscall handler registration.

#![no_std]

/// Returns a function pointer to the core syscall entry.
#[inline(always)]
pub fn syscall_entry_ptr() -> fn() {
    super::handle_interrupt
}

/// For portability, we return the entry pointer for the caller to wire up.

#[inline]
pub fn register_syscall_handler() -> fn() {
    syscall_entry_ptr()
}
