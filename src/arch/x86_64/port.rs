//! Port I/O utilities for x86_64.
//!
//! Provides unsafe wrappers around the `in` and `out` instructions,
//! enabling direct access to legacy hardware devices through I/O ports.
//!
//! ## Safety
//! - These functions perform raw hardware access; invalid ports or values
//!   can crash the system or cause undefined behavior.
//! - Always validate port numbers against chipset documentation.
//!
//! ## Usage
//! ```ignore
//! unsafe {
//!     let status: u8 = inb(0x64);  // read keyboard controller status
//!     outb(0x60, 0xFF);           // write command to keyboard data port
//! }
//! ```

/// Read a byte from the given I/O port.
///
/// # Safety
/// Caller must ensure that the port is valid and the operation is safe.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let mut val: u8;
    core::arch::asm!(
        "in al, dx",
        in("dx") port,
        out("al") val,
        options(nomem, nostack, preserves_flags)
    );
    val
}

/// Write a byte to the given I/O port.
///
/// # Safety
/// Caller must ensure that the port is valid and the operation is safe.
#[inline]
pub unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
        options(nomem, nostack, preserves_flags)
    );
}
