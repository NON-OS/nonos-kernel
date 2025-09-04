//! x86_64 architecture–specific modules for NØNOS kernel.
//!
//! This namespace collects all low-level hardware interfaces and
//! CPU/platform–specific functionality for x86_64 targets.
//!
//! Submodules:
//! - [`port`] : I/O port access using inline assembly (in/out instructions).
//! - [`vga`]  : Text-mode VGA driver for early boot diagnostics and logging.
//!
//! ## Design notes
//! - Keep x86_64-only code here; cross-arch abstractions should live
//!   under `crate::arch` root and delegate into this namespace.
//! - This makes it straightforward to add future `arch/arm` or
//!   `arch/riscv` backends without rewriting higher-level code.

pub mod port;
pub mod vga;
