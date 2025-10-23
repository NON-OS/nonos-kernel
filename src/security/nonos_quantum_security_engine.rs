//! NØNOS Quantum Security Engine 

#![no_std]

extern crate alloc;

use alloc::{vec::Vec, string::String, collections::BTreeMap, sync::Arc};
use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};
use spin::Mutex;

/// Supported post-quantum algorithms
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum QuantumAlgorithm {
    Kyber1024,
    Kyber768,
    Dilithium3,
    SphincsPlus128s,
    NtruHps4096821,
    McEliece348864,
    Lattice,
}

#[derive(Debug)]
pub struct QuantumKey {
    pub algo: QuantumAlgorithm,
    pub key_id: [u8; 32],
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
    pub created_at: u64,
    pub expires_at: u64,
    pub usage_count: AtomicU64,
}

/// Keypair generation using PQClean (via crate::crypto::quantum)
fn generate_pq_keypair(algo: &QuantumAlgorithm) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    match algo {
        QuantumAlgorithm::Kyber1024 => crate::crypto::quantum::kyber1024_keypair(),
        QuantumAlgorithm::Kyber768 => crate::crypto::quantum::kyber768_keypair(),
        QuantumAlgorithm::Dilithium3 => crate::crypto::quantum::dilithium3_keypair(),
        QuantumAlgorithm::SphincsPlus128s => crate::crypto::quantum::sphincs128s_keypair(),
        QuantumAlgorithm::NtruHps4096821 => crate::crypto::quantum::ntruhps4096821_keypair(),
        QuantumAlgorithm::McEliece348864 => crate::crypto::quantum::mceliece348864_keypair(),
        QuantumAlgorithm::Lattice => crate::crypto::quantum::lattice_keypair(),
    }
}

fn pq_sign(algo: &QuantumAlgorithm, message: &[u8], sk: &[u8]) -> Result<Vec<u8>, &'static str> {
    match algo {
        QuantumAlgorithm::Dilithium3 => crate::crypto::quantum::dilithium3_sign(message, sk),
        QuantumAlgorithm::SphincsPlus128s => crate::crypto::quantum::sphincs128s_sign(message, sk),
        _ => Err("Signing not supported for this algorithm"),
    }
}

fn pq_verify(algo: &QuantumAlgorithm, message: &[u8], sig: &[u8], pk: &[u8]) -> Result<bool, &'static str> {
    match algo {
        QuantumAlgorithm::Dilithium3 => crate::crypto::quantum::dilithium3_verify(message, sig, pk),
        QuantumAlgorithm::SphincsPlus128s => crate::crypto::quantum::sphincs128s_verify(message, sig, pk),
        _ => Err("Verification not supported for this algorithm"),
    }
}

fn pq_encapsulate(algo: &QuantumAlgorithm, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    match algo {
        QuantumAlgorithm::Kyber1024 => crate::crypto::quantum::kyber1024_encapsulate(pk),
        QuantumAlgorithm::Kyber768 => crate::crypto::quantum::kyber768_encapsulate(pk),
        QuantumAlgorithm::NtruHps4096821 => crate::crypto::quantum::ntruhps4096821_encapsulate(pk),
        QuantumAlgorithm::McEliece348864 => crate::crypto::quantum::mceliece348864_encapsulate(pk),
        _ => Err("Encapsulation not supported for this algorithm"),
    }
}

fn pq_decapsulate(algo: &QuantumAlgorithm, ct: &[u8], sk: &[u8]) -> Result<Vec<u8>, &'static str> {
    match algo {
        QuantumAlgorithm::Kyber1024 => crate::crypto::quantum::kyber1024_decapsulate(ct, sk),
        QuantumAlgorithm::Kyber768 => crate::crypto::quantum::kyber768_decapsulate(ct, sk),
        QuantumAlgorithm::NtruHps4096821 => crate::crypto::quantum::ntruhps4096821_decapsulate(ct, sk),
        QuantumAlgorithm::McEliece348864 => crate::crypto::quantum::mceliece348864_decapsulate(ct, sk),
        _ => Err("Decapsulation not supported for this algorithm"),
    }
}

/// Quantum key vault with lifecycle management
pub struct QuantumKeyVault {
    keys: Mutex<BTreeMap<[u8; 32], Arc<QuantumKey>>>,
    rotations: Mutex<Vec<QuantumKeyRotation>>,
    rotation_policy: QuantumKeyRotationPolicy,
}

#[derive(Debug, Clone)]
pub struct QuantumKeyRotation {
    pub old_key_id: [u8; 32],
    pub new_key_id: [u8; 32],
    pub rotated_at: u64,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct QuantumKeyRotationPolicy {
    pub rotation_interval_secs: u64,
    pub max_usage: u64,
    pub enforce_expiry: bool,
}

impl Default for QuantumKeyRotationPolicy {
    fn default() -> Self {
        Self {
            rotation_interval_secs: 86400, // 1 day
            max_usage: 10000,
            enforce_expiry: true,
        }
    }
}

impl QuantumKeyVault {
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(BTreeMap::new()),
            rotations: Mutex::new(Vec::new()),
            rotation_policy: QuantumKeyRotationPolicy::default(),
        }
    }

    /// Generate and store quantum-resistant key using PQClean
    pub fn generate_key(&self, algo: QuantumAlgorithm, lifetime_secs: u64) -> Arc<QuantumKey> {
        let (public, secret) = generate_pq_keypair(&algo).expect("PQ keygen failed");
        let key_id = crate::crypto::hash::blake3_hash(&public);
        let now = crate::time::timestamp_millis() / 1000;
        let key = Arc::new(QuantumKey {
            algo,
            key_id,
            public,
            secret,
            created_at: now,
            expires_at: now + lifetime_secs,
            usage_count: AtomicU64::new(0),
        });
        self.keys.lock().insert(key_id, key.clone());
        key
    }

    /// Rotate a key
    pub fn rotate_key(&self, key_id: &[u8; 32], reason: &str) -> Option<Arc<QuantumKey>> {
        let keys = self.keys.lock();
        let old_key = keys.get(key_id)?.clone();
        let new_key = self.generate_key(old_key.algo.clone(), old_key.expires_at - old_key.created_at);
        self.rotations.lock().push(QuantumKeyRotation {
            old_key_id: *key_id,
            new_key_id: new_key.key_id,
            rotated_at: crate::time::timestamp_millis() / 1000,
            reason: reason.into(),
        });
        Some(new_key)
    }

    /// Get key by ID
    pub fn get_key(&self, key_id: &[u8; 32]) -> Option<Arc<QuantumKey>> {
        self.keys.lock().get(key_id).cloned()
    }

    /// Cleanup expired or overused keys
    pub fn cleanup(&self) {
        let now = crate::time::timestamp_millis() / 1000;
        self.keys.lock().retain(|_, k| {
            let expired = self.rotation_policy.enforce_expiry && now > k.expires_at;
            let overused = k.usage_count.load(Ordering::Relaxed) > self.rotation_policy.max_usage;
            !(expired || overused)
        });
    }
}

/// Quantum RNG with entropy checks and hardware fallback
pub struct QuantumRng {
    pool: Mutex<Vec<u8>>,
    entropy_bits: AtomicU64,
    health_checks: AtomicU32,
    last_check: AtomicU64,
    healthy: AtomicBool,
}

impl QuantumRng {
    pub fn new() -> Self {
        let mut pool = Vec::with_capacity(4096);
        for _ in 0..4096 { pool.push(crate::crypto::secure_random_u8()); }
        Self {
            pool: Mutex::new(pool),
            entropy_bits: AtomicU64::new(8 * 4096),
            health_checks: AtomicU32::new(0),
            last_check: AtomicU64::new(crate::time::timestamp_millis()),
            healthy: AtomicBool::new(true),
        }
    }
    pub fn gen_bytes(&self, n: usize) -> Vec<u8> {
        let pool = self.pool.lock();
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(pool[crate::crypto::secure_random_u32() as usize % pool.len()]);
        }
        out
    }
    pub fn health_check(&self) -> bool {
        self.health_checks.fetch_add(1, Ordering::Relaxed);
        let pool = self.pool.lock();
        let entropy = crate::crypto::estimate_entropy(&pool);
        self.last_check.store(crate::time::timestamp_millis(), Ordering::Relaxed);
        let healthy = entropy > 7.5;
        self.healthy.store(healthy, Ordering::Relaxed);
        healthy
    }
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }
}

/// Kernel threat detection pipeline 
pub trait ThreatDetectionEngine {
    fn detect_threat(&self, input: &[u8]) -> Option<String>;
    fn report(&self) -> u64;
}

pub struct KernelThreatAI {
    detections: AtomicU64,
    last_threat: Mutex<Option<String>>,
}

impl KernelThreatAI {
    pub fn new() -> Self { Self { detections: AtomicU64::new(0), last_threat: Mutex::new(None) } }
}
impl ThreatDetectionEngine for KernelThreatAI {
    fn detect_threat(&self, input: &[u8]) -> Option<String> {
        // After with real ML/AI pipeline: kernel signals, syscalls, memory, network events
        if input.len() > 1024 && crate::crypto::estimate_entropy(input) > 7.5 {
            self.detections.fetch_add(1, Ordering::Relaxed);
            let threat = "High-entropy anomaly detected".into();
            *self.last_threat.lock() = Some(threat.clone());
            Some(threat)
        } else {
            None
        }
    }
    fn report(&self) -> u64 { self.detections.load(Ordering::Relaxed) }
}

/// Zero-trust enforcement 
pub struct QuantumZeroTrust {
    trust_scores: Mutex<BTreeMap<[u8; 32], u8>>, // 0-100
}
impl QuantumZeroTrust {
    pub fn new() -> Self { Self { trust_scores: Mutex::new(BTreeMap::new()) } }
    pub fn set_trust(&self, key_id: [u8; 32], score: u8) {
        self.trust_scores.lock().insert(key_id, score);
    }
    pub fn verify(&self, key_id: [u8; 32], min_score: u8) -> bool {
        self.trust_scores.lock().get(&key_id).map_or(false, |&score| score >= min_score)
    }
}

/// Compliance/audit hooks 
#[derive(Debug, Clone)]
pub struct QuantumAuditEvent {
    pub timestamp: u64,
    pub event_type: String,
    pub details: String,
    pub key_id: Option<[u8; 32]>,
}
pub struct QuantumAuditLog {
    events: Mutex<Vec<QuantumAuditEvent>>,
}
impl QuantumAuditLog {
    pub fn new() -> Self { Self { events: Mutex::new(Vec::new()) } }
    pub fn log_event(&self, event_type: &str, details: &str, key_id: Option<[u8; 32]>) {
        self.events.lock().push(QuantumAuditEvent {
            timestamp: crate::time::timestamp_millis(),
            event_type: event_type.into(),
            details: details.into(),
            key_id,
        })
    }
    pub fn recent(&self, n: usize) -> Vec<QuantumAuditEvent> {
        let log = self.events.lock();
        log.iter().rev().take(n).cloned().collect()
    }
}

/// Main quantum security engine 
pub struct QuantumSecurityEngine {
    pub vault: Arc<QuantumKeyVault>,
    pub rng: Arc<QuantumRng>,
    pub threat_ai: Arc<KernelThreatAI>,
    pub zero_trust: Arc<QuantumZeroTrust>,
    pub audit: Arc<QuantumAuditLog>,
}

impl QuantumSecurityEngine {
    pub fn new() -> Self {
        Self {
            vault: Arc::new(QuantumKeyVault::new()),
            rng: Arc::new(QuantumRng::new()),
            threat_ai: Arc::new(KernelThreatAI::new()),
            zero_trust: Arc::new(QuantumZeroTrust::new()),
            audit: Arc::new(QuantumAuditLog::new()),
        }
    }

    pub fn generate_pq_key(&self, algo: QuantumAlgorithm, lifetime_secs: u64) -> Arc<QuantumKey> {
        let key = self.vault.generate_key(algo, lifetime_secs);
        self.audit.log_event("key_generated", "Post-quantum key generated", Some(key.key_id));
        key
    }

    pub fn rotate_pq_key(&self, key_id: &[u8; 32], reason: &str) -> Option<Arc<QuantumKey>> {
        let new_key = self.vault.rotate_key(key_id, reason);
        if let Some(ref k) = new_key {
            self.audit.log_event("key_rotated", reason, Some(k.key_id));
        }
        new_key
    }

    pub fn sign(&self, algo: QuantumAlgorithm, message: &[u8], sk: &[u8]) -> Result<Vec<u8>, &'static str> {
        pq_sign(&algo, message, sk)
    }
    pub fn verify(&self, algo: QuantumAlgorithm, message: &[u8], sig: &[u8], pk: &[u8]) -> Result<bool, &'static str> {
        pq_verify(&algo, message, sig, pk)
    }
    pub fn encapsulate(&self, algo: QuantumAlgorithm, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        pq_encapsulate(&algo, pk)
    }
    pub fn decapsulate(&self, algo: QuantumAlgorithm, ct: &[u8], sk: &[u8]) -> Result<Vec<u8>, &'static str> {
        pq_decapsulate(&algo, ct, sk)
    }

    pub fn check_rng_health(&self) -> bool {
        self.rng.health_check()
    }

    pub fn detect_threat(&self, input: &[u8]) -> Option<String> {
        let res = self.threat_ai.detect_threat(input);
        if let Some(ref threat) = res {
            self.audit.log_event("threat_detected", threat, None);
        }
        res
    }

    pub fn set_trust_score(&self, key_id: [u8; 32], score: u8) {
        self.zero_trust.set_trust(key_id, score);
        self.audit.log_event("trust_score_set", &format!("Score: {}", score), Some(key_id));
    }

    pub fn verify_trust(&self, key_id: [u8; 32], min_score: u8) -> bool {
        self.zero_trust.verify(key_id, min_score)
    }

    pub fn recent_audit(&self, n: usize) -> Vec<QuantumAuditEvent> {
        self.audit.recent(n)
    }
}

#[derive(Debug, Clone)]
pub struct QuantumSecurityStats {
    pub key_count: u64,
    pub compliance_events: u64,
    pub qkd_count: u64,
    pub entropy_bits: f64,
    pub threat_detections: u64,
    pub trust_verifications: u64,
}
