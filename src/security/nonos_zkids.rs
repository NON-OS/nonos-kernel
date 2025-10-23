//! NØNOS ZKIDS – Zero-Knowledge Identity System 

#![no_std]

extern crate alloc;

use alloc::{vec::Vec, string::String, collections::BTreeMap};
use spin::{RwLock, Once};
use crate::crypto::{generate_plonk_proof, verify_plonk_proof, hash::blake3_hash, sig::ed25519::Ed25519Signature, fill_random};

// Define macros at top of file
#[macro_export]
macro_rules! require_capability {
    ($session:expr, $cap:expr) => {
        if !crate::security::nonos_zkids::has_capability($session, &$cap) {
            return Err("Insufficient privileges");
        }
    };
}

#[macro_export]
macro_rules! require_admin {
    ($session:expr) => {
        require_capability!($session, crate::security::nonos_zkids::Capability::SystemAdmin);
    };
}

/// ZKID cryptographic identity
#[derive(Clone, Debug)]
pub struct ZkId {
    pub id_hash: [u8; 32],
    pub public_key: [u8; 32],
    pub capabilities: Vec<Capability>,
    pub created_at: u64,
    pub last_auth: u64,
    pub auth_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Capability {
    SystemAdmin,
    ProcessManager,
    MemoryManager,
    NetworkAdmin,
    FileSystem,
    CryptoOperator,
    ModuleLoader,
    DebugAccess,
    TimeCritical,
    Custom(String),
}

#[derive(Clone)]
pub struct AuthChallenge {
    pub challenge_id: [u8; 32],
    pub nonce: [u8; 32],
    pub timestamp: u64,
    pub required_capabilities: Vec<Capability>,
}

#[derive(Clone)]
pub struct AuthResponse {
    pub challenge_id: [u8; 32],
    pub zkproof: Vec<u8>, // PLONK proof bytes
    pub signature: Ed25519Signature,
    pub requested_session_duration: u64,
}

#[derive(Clone)]
pub struct AuthSession {
    pub session_id: [u8; 32],
    pub zkid: ZkId,
    pub capabilities: Vec<Capability>,
    pub created_at: u64,
    pub expires_at: u64,
    pub last_activity: u64,
}

/// ZKIDS Manager 
pub struct ZkidsManager {
    pub registered_ids: BTreeMap<[u8; 32], ZkId>,
    pub active_sessions: BTreeMap<[u8; 32], AuthSession>,
    pub pending_challenges: BTreeMap<[u8; 32], AuthChallenge>,
    pub config: ZkidsConfig,
}

#[derive(Clone, Copy)]
pub struct ZkidsConfig {
    pub max_registered_ids: usize,
    pub session_timeout_seconds: u64,
    pub challenge_timeout_seconds: u64,
    pub require_zk_proofs: bool,
    pub enable_capability_inheritance: bool,
}

impl Default for ZkidsConfig {
    fn default() -> Self {
        Self {
            max_registered_ids: 1024,
            session_timeout_seconds: 3600,
            challenge_timeout_seconds: 300,
            require_zk_proofs: true,
            enable_capability_inheritance: false,
        }
    }
}

static ZKIDS_MANAGER: Once<RwLock<ZkidsManager>> = Once::new();

fn get_zkids_manager() -> &'static RwLock<ZkidsManager> {
    ZKIDS_MANAGER.call_once(|| RwLock::new(ZkidsManager {
        registered_ids: BTreeMap::new(),
        active_sessions: BTreeMap::new(),
        pending_challenges: BTreeMap::new(),
        config: ZkidsConfig::default(),
    }))
}

/// Initialize ZKIDS subsystem (creates genesis admin identity)
pub fn init_zkids() -> Result<(), &'static str> {
    crate::log::logger::log_info!("[ZKIDS] Initializing Zero-Knowledge Identity System");
    let genesis_key = crate::crypto::generate_secure_key();
    let genesis_public = derive_public_key(&genesis_key);
    let id_hash = blake3_hash(&genesis_public);
    let genesis = ZkId {
        id_hash,
        public_key: genesis_public,
        capabilities: vec![
            Capability::SystemAdmin,
            Capability::ProcessManager,
            Capability::MemoryManager,
            Capability::NetworkAdmin,
            Capability::FileSystem,
            Capability::CryptoOperator,
            Capability::ModuleLoader,
            Capability::DebugAccess,
            Capability::TimeCritical,
        ],
        created_at: current_timestamp(),
        last_auth: 0,
        auth_count: 0,
    };
    let mut mgr = get_zkids_manager().write();
    mgr.registered_ids.insert(id_hash, genesis);
    Ok(())
}

/// Register a new ZKID (public key, capabilities)
pub fn register_zkid(public_key: [u8; 32], capabilities: Vec<Capability>) -> Result<[u8; 32], &'static str> {
    let mut mgr = get_zkids_manager().write();
    if mgr.registered_ids.len() >= mgr.config.max_registered_ids {
        return Err("Maximum number of registered IDs reached");
    }
    let id_hash = blake3_hash(&public_key);
    if mgr.registered_ids.contains_key(&id_hash) { return Err("ID already registered"); }
    let zkid = ZkId {
        id_hash,
        public_key,
        capabilities,
        created_at: current_timestamp(),
        last_auth: 0,
        auth_count: 0,
    };
    mgr.registered_ids.insert(id_hash, zkid);
    Ok(id_hash)
}

/// Create authentication challenge for a ZKID
pub fn create_auth_challenge(id_hash: [u8; 32], required_caps: Vec<Capability>) -> Result<AuthChallenge, &'static str> {
    let mgr = get_zkids_manager().read();
    let zkid = mgr.registered_ids.get(&id_hash).ok_or("Unknown identity")?;
    for required_cap in &required_caps {
        if !zkid.capabilities.contains(required_cap) {
            return Err("Insufficient capabilities");
        }
    }
    drop(mgr);
    let challenge_id = secure_random_bytes();
    let nonce = secure_random_bytes();
    let challenge = AuthChallenge {
        challenge_id,
        nonce,
        timestamp: current_timestamp(),
        required_capabilities: required_caps,
    };
    let mut mgr = get_zkids_manager().write();
    mgr.pending_challenges.insert(challenge_id, challenge.clone());
    Ok(challenge)
}

/// Authenticate using ZK proof and Ed25519 signature
pub fn authenticate_with_zkproof(id_hash: [u8; 32], response: AuthResponse) -> Result<[u8; 32], &'static str> {
    let mut mgr = get_zkids_manager().write();
    let challenge = mgr.pending_challenges.remove(&response.challenge_id).ok_or("Invalid or expired challenge")?;
    let current_time = current_timestamp();
    if current_time - challenge.timestamp > mgr.config.challenge_timeout_seconds {
        return Err("Challenge expired");
    }
    let mut zkid = mgr.registered_ids.get(&id_hash).ok_or("Unknown identity")?.clone();

    // Zero-knowledge proof verification
    if mgr.config.require_zk_proofs {
        let proof_statement = create_proof_statement(&challenge, &zkid);
        let verification_key = derive_verification_key(&zkid);
        match verify_plonk_proof(&proof_statement, &response.zkproof) {
            Ok(is_valid) => {
                if !is_valid { return Err("Zero-knowledge proof verification failed"); }
            }
            Err(e) => {
                crate::log_warn!("[ZKIDS] Proof verification error: {}", e);
                return Err("Proof verification error");
            }
        }
    }

    // Ed25519 signature verification
    if !verify_signature(&response.signature, &challenge.challenge_id, &zkid.public_key) {
        return Err("Invalid signature");
    }

    // Create session
    let session_id = secure_random_bytes();
    let session = AuthSession {
        session_id,
        zkid: zkid.clone(),
        capabilities: challenge.required_capabilities,
        created_at: current_time,
        expires_at: current_time + response.requested_session_duration.min(mgr.config.session_timeout_seconds),
        last_activity: current_time,
    };
    mgr.active_sessions.insert(session_id, session);
    zkid.last_auth = current_time;
    zkid.auth_count += 1;
    mgr.registered_ids.insert(id_hash, zkid);
    Ok(session_id)
}

/// Validate session and return capabilities
pub fn validate_session(session_id: [u8; 32]) -> Result<Vec<Capability>, &'static str> {
    let mut mgr = get_zkids_manager().write();
    let session = mgr.active_sessions.get_mut(&session_id).ok_or("Invalid session")?;
    let current_time = current_timestamp();
    if current_time > session.expires_at {
        mgr.active_sessions.remove(&session_id);
        return Err("Session expired");
    }
    session.last_activity = current_time;
    Ok(session.capabilities.clone())
}

/// Check if session has capability
pub fn has_capability(session_id: [u8; 32], capability: &Capability) -> bool {
    validate_session(session_id).map_or(false, |caps| caps.contains(capability))
}

/// Export ZKID (admin only)
pub fn export_zkid(session_id: [u8; 32], target_id: [u8; 32]) -> Result<Vec<u8>, &'static str> {
    require_admin!(session_id);
    let mgr = get_zkids_manager().read();
    let zkid = mgr.registered_ids.get(&target_id).ok_or("ZKID not found")?;
    let mut export_data = Vec::new();
    export_data.extend_from_slice(&zkid.id_hash);
    export_data.extend_from_slice(&zkid.public_key);
    Ok(export_data)
}

/// Import ZKID (admin only)
pub fn import_zkid(session_id: [u8; 32], import_data: &[u8]) -> Result<[u8; 32], &'static str> {
    require_admin!(session_id);
    if import_data.len() < 64 { return Err("Invalid import data"); }
    let mut id_hash = [0u8; 32];
    let mut public_key = [0u8; 32];
    id_hash.copy_from_slice(&import_data[0..32]);
    public_key.copy_from_slice(&import_data[32..64]);
    let capabilities = vec![Capability::FileSystem, Capability::ProcessManager];
    let mut mgr = get_zkids_manager().write();
    let zkid = ZkId {
        id_hash,
        public_key,
        capabilities,
        created_at: current_timestamp(),
        last_auth: 0,
        auth_count: 0,
    };
    mgr.registered_ids.insert(id_hash, zkid);
    Ok(id_hash)
}

/// Clean up expired sessions and challenges
pub fn cleanup_expired() {
    let mut mgr = get_zkids_manager().write();
    let current_time = current_timestamp();
    let expired_sessions: Vec<[u8; 32]> = mgr.active_sessions.iter()
        .filter(|(_, s)| current_time > s.expires_at)
        .map(|(id, _)| *id).collect();
    for session_id in expired_sessions { mgr.active_sessions.remove(&session_id); }
    let expired_challenges: Vec<[u8; 32]> = mgr.pending_challenges.iter()
        .filter(|(_, c)| current_time - c.timestamp > mgr.config.challenge_timeout_seconds)
        .map(|(id, _)| *id).collect();
    for challenge_id in expired_challenges { mgr.pending_challenges.remove(&challenge_id); }
}

/// System statistics
pub fn get_zkids_stats() -> ZkidsStats {
    let mgr = get_zkids_manager().read();
    ZkidsStats {
        registered_ids: mgr.registered_ids.len(),
        active_sessions: mgr.active_sessions.len(),
        pending_challenges: mgr.pending_challenges.len(),
        total_authentications: mgr.registered_ids.values().map(|zkid| zkid.auth_count).sum(),
    }
}

#[derive(Clone, Debug)]
pub struct ZkidsStats {
    pub registered_ids: usize,
    pub active_sessions: usize,
    pub pending_challenges: usize,
    pub total_authentications: u64,
}

// Helper functions

fn derive_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    blake3_hash(private_key)
}

fn secure_random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes);
    bytes
}

fn create_proof_statement(challenge: &AuthChallenge, zkid: &ZkId) -> Vec<u8> {
    let mut statement = Vec::new();
    statement.extend_from_slice(&challenge.challenge_id);
    statement.extend_from_slice(&challenge.nonce);
    statement.extend_from_slice(&zkid.id_hash);
    statement.extend_from_slice(&zkid.public_key);
    statement.extend_from_slice(&challenge.timestamp.to_le_bytes());
    for cap in &challenge.required_capabilities {
        statement.extend_from_slice(&capability_to_bytes(cap));
    }
    statement
}

fn derive_verification_key(zkid: &ZkId) -> Vec<u8> {
    let mut key_material = Vec::new();
    key_material.extend_from_slice(&zkid.public_key);
    key_material.extend_from_slice(&zkid.id_hash);
    key_material.extend_from_slice(&zkid.created_at.to_le_bytes());
    let mut verification_key = vec![0u8; 32];
    let derived_key = blake3_hash(&key_material);
    verification_key.copy_from_slice(&derived_key);
    verification_key
}

fn capability_to_bytes(capability: &Capability) -> [u8; 32] {
    let cap_str = match capability {
        Capability::SystemAdmin => "system_admin",
        Capability::ProcessManager => "process_manager",
        Capability::MemoryManager => "memory_manager",
        Capability::NetworkAdmin => "network_admin",
        Capability::FileSystem => "filesystem",
        Capability::CryptoOperator => "crypto_operator",
        Capability::ModuleLoader => "module_loader",
        Capability::DebugAccess => "debug_access",
        Capability::TimeCritical => "time_critical",
        Capability::Custom(name) => name,
    };
    blake3_hash(cap_str.as_bytes())
}

fn verify_signature(signature: &Ed25519Signature, message: &[u8], public_key: &[u8; 32]) -> bool {
    match crate::crypto::sig::ed25519::verify_signature(signature, message, public_key) {
        Ok(is_valid) => is_valid,
        Err(e) => {
            crate::log_warn!("[ZKIDS] Signature verification error: {}", e);
            false
        }
    }
}

fn current_timestamp() -> u64 {
    crate::arch::x86_64::time::timer::now_ns() / 1_000_000_000
}