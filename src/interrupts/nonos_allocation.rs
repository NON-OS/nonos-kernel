//! Dynamic interrupt vector allocation/registration.

#![no_std]

use spin::RwLock;

use x86_64::structures::idt::InterruptStackFrame;

type NoErrHandler = fn(InterruptStackFrame);
type ErrHandler = fn(InterruptStackFrame, u64);

struct Registry {
    reserved: [bool; 256],
    noerr: [Option<NoErrHandler>; 256],
    err: [Option<ErrHandler>; 256],
}

static REG: RwLock<Registry> = RwLock::new(Registry {
    reserved: [false; 256],
    noerr: [None; 256],
    err: [None; 256],
});

/// Mark essential vectors as reserved (CPU exceptions 0..31 and known IRQs/syscall).
pub fn init_interrupt_allocation() {
    let mut r = REG.write();
    for i in 0..32 {
        r.reserved[i] = true;
    }
    // Timer(32), Keyboard(33), Syscall(0x80)
    r.reserved[32] = true;
    r.reserved[33] = true;
    r.reserved[0x80] = true;
}

/// Allocate a free vector in 32..=255.
pub fn allocate_vector() -> Option<u8> {
    let mut r = REG.write();
    for v in 32u8..=255u8 {
        if !r.reserved[v as usize] && r.noerr[v as usize].is_none() && r.err[v as usize].is_none() {
            r.reserved[v as usize] = true;
            return Some(v);
        }
    }
    None
}

/// Register a no-error-code handler at a given vector (must be >= 32).
pub fn register_interrupt_handler(vector: u8, handler: NoErrHandler) -> Result<(), &'static str> {
    if vector < 32 {
        return Err("vector reserved");
    }
    let mut r = REG.write();
    if r.noerr[vector as usize].is_some() || r.err[vector as usize].is_some() {
        return Err("vector busy");
    }
    r.noerr[vector as usize] = Some(handler);
    Ok(())
}

/// fetch a registered handler.
pub(crate) fn get_noerr(vector: u8) -> Option<NoErrHandler> {
    REG.read().noerr[vector as usize]
}
pub(crate) fn get_err(vector: u8) -> Option<ErrHandler> {
    REG.read().err[vector as usize]
}
