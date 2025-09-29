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

/// Cryptographic capability token issuer
pub struct CapabilityIssuer {
    private_key: [u8; 32],
    pub_key_hash: [u8; 32],
}

impl CapabilityIssuer {
    /// Create new capability issuer with cryptographic keys
    pub fn new() -> Self {
        // Generate key pair using kernel entropy
        let private_key = crate::crypto::entropy::get_random_bytes_32();
        let pub_key_hash = crate::crypto::hash::blake3_hash(&private_key);
        
        Self {
            private_key,
            pub_key_hash,
        }
    }

    /// Issue a cryptographically signed capability token
    pub fn issue_token(&self, module_name: &'static str, capabilities: Vec<Capability>, lifetime_secs: u64) -> Result<SignedCapabilityToken, &'static str> {
        let current_time = crate::time::timestamp_millis();
        let lifetime_ticks = lifetime_secs * 1000; // Convert to milliseconds
        
        let token = CapabilityToken {
            owner_module: module_name,
            permissions: capabilities.into_iter().collect(),
            issued_at: current_time,
            scope_lifetime_ticks: lifetime_ticks,
        };

        // Create signature
        let token_data = format!("{}:{}:{}:{}", 
            module_name,
            current_time,
            lifetime_ticks,
            token.permissions.iter().map(|c| c.to_u8()).collect::<Vec<_>>().len()
        );
        
        let signature = self.sign_data(token_data.as_bytes())?;
        
        Ok(SignedCapabilityToken {
            token,
            signature,
            issuer_key_hash: self.pub_key_hash,
        })
    }

    /// Sign data with private key
    fn sign_data(&self, data: &[u8]) -> Result<[u8; 64], &'static str> {
        // Use Ed25519 signature
        crate::crypto::sig::ed25519_sign(&self.private_key, data)
    }

    /// Verify a signed token
    pub fn verify_token(&self, signed_token: &SignedCapabilityToken) -> Result<bool, &'static str> {
        // Check issuer
        if signed_token.issuer_key_hash != self.pub_key_hash {
            return Ok(false);
        }

        // Check expiration
        if !signed_token.token.is_valid()? {
            return Ok(false);
        }

        // Verify signature
        let token_data = format!("{}:{}:{}:{}", 
            signed_token.token.owner_module,
            signed_token.token.issued_at,
            signed_token.token.scope_lifetime_ticks,
            signed_token.token.permissions.len()
        );

        let public_key = self.derive_public_key(&self.private_key)?;
        crate::crypto::sig::ed25519_verify(&public_key, token_data.as_bytes(), &signed_token.signature)
    }

    /// Derive public key from private key
    fn derive_public_key(&self, private_key: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        crate::crypto::sig::ed25519_derive_public_key(private_key)
    }
}

/// Cryptographically signed capability token
#[derive(Debug, Clone)]
pub struct SignedCapabilityToken {
    pub token: CapabilityToken,
    pub signature: [u8; 64],
    pub issuer_key_hash: [u8; 32],
}

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
