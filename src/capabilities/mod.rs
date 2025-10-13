#![no_std]

extern crate alloc;

pub mod delegation;
pub mod audit;
pub mod resource;
pub mod multisig;
pub mod chain;

use alloc::{vec::Vec, collections::{BTreeMap, BTreeSet}};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Once, RwLock};

pub use delegation::*;
pub use audit::*;
pub use resource::*;
pub use multisig::*;
pub use chain::*;

/// Core system capabilities (bit-packed into a u64 in signatures)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    CoreExec,       // Basic execution rights
    IO,             // Input/output operations
    Network,        // Network access
    IPC,            // Inter-process communication
    Memory,         // Memory allocation
    Crypto,         // Cryptographic operations
    FileSystem,     // Filesystem access
    Hardware,       // Direct hardware access
    Debug,          // Debug/profiling access
    Admin,          // Administrative privileges
}

impl Capability {
    #[inline]
    fn bit(self) -> u64 {
        match self {
            Capability::CoreExec    => 1 << 0,
            Capability::IO          => 1 << 1,
            Capability::Network     => 1 << 2,
            Capability::IPC         => 1 << 3,
            Capability::Memory      => 1 << 4,
            Capability::Crypto      => 1 << 5,
            Capability::FileSystem  => 1 << 6,
            Capability::Hardware    => 1 << 7,
            Capability::Debug       => 1 << 8,
            Capability::Admin       => 1 << 9,
        }
    }
}

#[inline]
pub fn caps_to_bits(caps: &[Capability]) -> u64 {
    caps.iter().fold(0u64, |acc, c| acc | c.bit())
}

#[inline]
pub fn bits_to_caps(bits: u64) -> Vec<Capability> {
    let all = [
        Capability::CoreExec, Capability::IO, Capability::Network, Capability::IPC, Capability::Memory,
        Capability::Crypto, Capability::FileSystem, Capability::Hardware, Capability::Debug, Capability::Admin
    ];
    let mut v = Vec::new();
    for c in all {
        if bits & c.bit() != 0 { v.push(c); }
    }
    v
}

/// Cryptographically signed capability token (HMAC-BLAKE3 keyed by the kernel signing key)
#[derive(Debug, Clone)]
pub struct CapabilityToken {
    pub owner_module: u64,          // issuer or subject module id
    pub permissions: Vec<Capability>,
    pub expires_at_ms: Option<u64>,  // absolute ms since epoch (kernel time base)
    pub nonce: u64,                  // uniqueness/anti-replay (ts||counter)
    pub signature: [u8; 64],         // mac1||mac2 (two diversified keyed hashes)
}

impl CapabilityToken {
    /// Check if token grants specific capability
    #[inline]
    pub fn grants(&self, cap: Capability) -> bool {
        self.permissions.iter().any(|c| *c == cap)
    }

    /// Returns true if the token has not expired
    #[inline]
    pub fn not_expired(&self) -> bool {
        match self.expires_at_ms {
            Some(exp) => crate::time::timestamp_millis() < exp,
            None => true,
        }
    }

    /// Verify signature and revocation, and check expiry
    pub fn is_valid(&self) -> bool {
        verify_token(self)
            && self.not_expired()
            && !is_revoked(self.owner_module, self.nonce)
    }

    /// Serialize to a compact binary format:
    /// [ver:1][owner:8][perms_bits:8][expires:8][nonce:8][sig:64]
    pub fn to_bytes(&self) -> [u8; 1 + 8 + 8 + 8 + 8 + 64] {
        const VER: u8 = 1;
        let mut out = [0u8; 1 + 8 + 8 + 8 + 8 + 64];
        out[0] = VER;
        out[1..9].copy_from_slice(&self.owner_module.to_le_bytes());
        let bits = caps_to_bits(&self.permissions);
        out[9..17].copy_from_slice(&bits.to_le_bytes());
        let exp = self.expires_at_ms.unwrap_or(0);
        out[17..25].copy_from_slice(&exp.to_le_bytes());
        out[25..33].copy_from_slice(&self.nonce.to_le_bytes());
        out[33..97].copy_from_slice(&self.signature);
        out
    }

    /// Deserialize from compact binary format (as above)
    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() != 1 + 8 + 8 + 8 + 8 + 64 { return Err("cap: size"); }
        if buf[0] != 1 { return Err("cap: ver"); }
        let owner = u64::from_le_bytes(buf[1..9].try_into().unwrap());
        let bits = u64::from_le_bytes(buf[9..17].try_into().unwrap());
        let exp = u64::from_le_bytes(buf[17..25].try_into().unwrap());
        let nonce = u64::from_le_bytes(buf[25..33].try_into().unwrap());
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&buf[33..97]);

        Ok(Self {
            owner_module: owner,
            permissions: bits_to_caps(bits),
            expires_at_ms: if exp == 0 { None } else { Some(exp) },
            nonce,
            signature: sig,
        })
    }
}

// ---------- Signing key management (kernel) ----------

static SIGNING_KEY: Once<[u8; 32]> = Once::new();

/// Install the 32-byte HMAC-BLAKE3 signing key (must be called during boot from a secure source).
/// Returns Err if the key is already set or length is invalid.
pub fn set_signing_key(key: &[u8]) -> Result<(), &'static str> {
    if key.len() != 32 { return Err("cap: key size"); }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(key);
    let mut ok = true;
    SIGNING_KEY.call_once(|| arr).map_err(|_| { ok = false; () }).ok();
    if ok { Ok(()) } else { Err("cap: key already set") }
}

#[inline]
pub fn has_signing_key() -> bool {
    SIGNING_KEY.get().is_some()
}

#[inline]
pub fn signing_key() -> Option<&'static [u8; 32]> {
    SIGNING_KEY.get()
}

// ---------- MAC/signature helpers ----------

#[inline]
fn token_material(owner: u64, bits: u64, expires_ms: u64, nonce: u64) -> [u8; 8 + 8 + 8 + 8] {
    let mut out = [0u8; 8 + 8 + 8 + 8];
    out[0..8].copy_from_slice(&owner.to_le_bytes());
    out[8..16].copy_from_slice(&bits.to_le_bytes());
    out[16..24].copy_from_slice(&expires_ms.to_le_bytes());
    out[24..32].copy_from_slice(&nonce.to_le_bytes());
    out
}

fn mac64(key: &[u8; 32], mat: &[u8]) -> [u8; 64] {
    let mac1 = blake3::keyed_hash(key, mat);
    let mut ctx2 = blake3::Hasher::new_keyed(key);
    ctx2.update(mat);
    ctx2.update(b"CAP2");
    let mac2 = ctx2.finalize();
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(mac1.as_bytes());
    out[32..64].copy_from_slice(mac2.as_bytes());
    out
}

/// Sign a token in-place (fills nonce if 0)
pub fn sign_token(tok: &mut CapabilityToken) -> Result<(), &'static str> {
    let key = signing_key().ok_or("cap: missing signing key")?;
    let bits = caps_to_bits(&tok.permissions);
    if tok.nonce == 0 {
        tok.nonce = default_nonce();
    }
    let exp = tok.expires_at_ms.unwrap_or(0);
    let mat = token_material(tok.owner_module, bits, exp, tok.nonce);
    tok.signature = mac64(key, &mat);
    Ok(())
}

/// Verify token signature using the current signing key
pub fn verify_token(tok: &CapabilityToken) -> bool {
    let Some(key) = signing_key() else { return false; };
    let bits = caps_to_bits(&tok.permissions);
    let exp = tok.expires_at_ms.unwrap_or(0);
    let mat = token_material(tok.owner_module, bits, exp, tok.nonce);
    mac64(key, &mat) == tok.signature
}

// ---------- Token creation & helpers ----------

static NONCE_CTR: AtomicU64 = AtomicU64::new(1);

#[inline]
pub fn default_nonce() -> u64 {
    let t = crate::time::timestamp_millis();
    let c = NONCE_CTR.fetch_add(1, Ordering::Relaxed) & 0xFFFF_FFFF;
    (t << 32) ^ c
}

/// Create and sign a token for an owner with caps and optional ttl_ms (None => no expiry).
pub fn create_token(owner_module: u64, caps: &[Capability], ttl_ms: Option<u64>) -> Result<CapabilityToken, &'static str> {
    let now = crate::time::timestamp_millis();
    let exp = ttl_ms.map(|t| now.saturating_add(t));
    let mut tok = CapabilityToken {
        owner_module,
        permissions: caps.to_vec(),
        expires_at_ms: exp,
        nonce: 0,
        signature: [0u8; 64],
    };
    sign_token(&mut tok)?;
    Ok(tok)
}

// ---------- Revocation list (owner, nonce) ----------

static REVOKED: RwLock<BTreeSet<(u64, u64)>> = RwLock::new(BTreeSet::new());

pub fn revoke_token(owner_module: u64, nonce: u64) {
    REVOKED.write().insert((owner_module, nonce));
}

#[inline]
fn is_revoked(owner_module: u64, nonce: u64) -> bool {
    REVOKED.read().contains(&(owner_module, nonce))
}

// ---------- Role presets ----------

pub mod roles {
    use super::{Capability, Capability::*};

    pub const KERNEL: &[Capability] = &[
        CoreExec, IO, Network, IPC, Memory, Crypto, FileSystem, Hardware, Debug, Admin
    ];

    pub const SYSTEM_SERVICE: &[Capability] = &[
        CoreExec, IPC, Memory, FileSystem,
    ];

    pub const SANDBOXED_MOD: &[Capability] = &[
        CoreExec, IPC, Memory,
    ];
}
