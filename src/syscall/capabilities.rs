//! NØNOS Capability Enforcement Layer
//!
//! This module defines a strict zero-trust access control framework using
//! cryptographically bound capability tokens. Each `.mod` binary or kernel task
//! must operate within a declared security perimeter enforced by these tokens.
//! This system enables syscall restriction, IPC boundary control, and optional
//! zero-knowledge delegation in future phases.

use alloc::{string::String, format, vec::Vec, collections::BTreeSet};
use core::fmt;

/// Enum of all secure kernel-level privileges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Capability {
    CoreExec = 0x01,   // Kernel/syscall access, spawn, time
    IO = 0x02,         // VGA/logging/UART output
    SecureMem = 0x03,  // RAM-only vault / secrets / keyslots
    Crypto = 0x04,     // Entropy, hashing, zkAuth
    IPC = 0x05,        // Inter-module messaging / sockets
    Filesystem = 0x06, // Persistent read/write
    Net = 0x07,        // Mesh routing / encrypted overlay
    ModLoader = 0x08,  // Module validation / registration
    Admin = 0x09,      // Administrative privileges
}

impl Capability {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}

impl TryFrom<u8> for Capability {
    type Error = &'static str;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Capability::CoreExec),
            0x02 => Ok(Capability::IO),
            0x03 => Ok(Capability::SecureMem),
            0x04 => Ok(Capability::Crypto),
            0x05 => Ok(Capability::IPC),
            0x06 => Ok(Capability::Filesystem),
            0x07 => Ok(Capability::Net),
            0x08 => Ok(Capability::ModLoader),
            0x09 => Ok(Capability::Admin),
            _ => Err("Invalid capability value"),
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Issued to each module or context during runtime entry
#[derive(Debug, Clone)]
pub struct CapabilityToken {
    pub owner_module: &'static str,
    pub permissions: BTreeSet<Capability>,
    pub issued_at: u64,
    pub scope_lifetime_ticks: u64,
}

impl CapabilityToken {
    /// Validates the presence of a permission
    pub fn has(&self, cap: Capability) -> bool {
        self.permissions.contains(&cap)
    }
    
    /// Alias for has() - checks if token grants a capability
    pub fn grants(&self, cap: Capability) -> bool {
        self.has(cap)
    }

    /// Alternative method name for grants() - checks if token grants a capability
    pub fn grants_capability(&self, cap: &Capability) -> bool {
        self.has(*cap)
    }

    /// Validates if token is still valid (not expired)
    pub fn is_valid(&self) -> Result<bool, &'static str> {
        // Get current time from kernel time system
        let current_time = crate::time::timestamp_millis();
        let expires_at = self.issued_at + self.scope_lifetime_ticks;
        Ok(current_time < expires_at)
    }

    /// Returns printable summary of allowed capabilities
    pub fn describe(&self) -> String {
        let caps: Vec<String> = self.permissions.iter().map(|c| format!("{}", c)).collect();
        format!("Token[{}] => [{}]", self.owner_module, caps.join(", "))
    }
}

/// Global static token used by syscall routing context
static mut CURRENT_TOKEN: Option<CapabilityToken> = None;

/// Called during task or module execution bootstrap
pub fn set_current_token(token: CapabilityToken) {
    unsafe {
        CURRENT_TOKEN = Some(token);
    }
}

/// Clears token on task shutdown or privilege exit
pub fn clear_token() {
    unsafe {
        CURRENT_TOKEN = None;
    }
}

/// Used by kernel services and syscalls to check access rights
pub fn verify_capability(required: Capability) -> bool {
    unsafe {
        match &CURRENT_TOKEN {
            Some(tok) => tok.has(required),
            None => false,
        }
    }
}

/// Returns full printable capability trace for diagnostics
pub fn debug_token() -> String {
    unsafe {
        match &CURRENT_TOKEN {
            Some(tok) => tok.describe(),
            None => "<null token>".into(),
        }
    }
}

/// Initialize the capability system
pub fn init_capabilities() {
    unsafe {
        CURRENT_TOKEN = None;
    }
    
    // Log capability system initialization
    if let Some(logger) = crate::log::logger::try_get_logger() {
        logger.log("[SYSCALL] Capability system initialized");
    }
}
