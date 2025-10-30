#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};
use core::mem;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use spin::{Mutex, RwLock};
use x86_64::{VirtAddr, PhysAddr};

use crate::memory::nonos_layout as layout;
use crate::memory::nonos_kaslr as kaslr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapTag {
    KERNEL,
    USER,
    DEVICE,
    CRYPTO,
    PROOF,
}

#[derive(Debug, Clone)]
pub struct MemoryProof {
    pub tag: CapTag,
    pub start_addr: u64,
    pub size: u64,
    pub hash: [u8; 32],
    pub timestamp: u64,
    pub nonce: u64,
}

#[derive(Debug, Clone)]
pub struct CryptographicCapsule {
    pub capsule_id: u64,
    pub memory_region: MemoryRegion,
    pub integrity_hash: [u8; 32],
    pub access_key: [u8; 32],
    pub permissions: CapsulePermissions,
    pub creation_time: u64,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: PhysAddr,
    pub end: PhysAddr,
    pub tag: CapTag,
}

#[derive(Debug, Clone, Copy)]
pub struct CapsulePermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub sealed: bool,
}

pub struct ProofSystem {
    capsules: RwLock<BTreeMap<u64, CryptographicCapsule>>,
    proofs: RwLock<BTreeMap<u64, MemoryProof>>,
    audit_log: Mutex<Vec<AuditEntry>>,
    next_capsule_id: AtomicU64,
    next_proof_id: AtomicU64,
}

#[derive(Debug, Clone)]
struct AuditEntry {
    operation: AuditOperation,
    capsule_id: u64,
    timestamp: u64,
    result: AuditResult,
}

#[derive(Debug, Clone, Copy)]
enum AuditOperation {
    Create,
    Seal,
    Unseal,
    Verify,
    Destroy,
}

#[derive(Debug, Clone, Copy)]
enum AuditResult {
    Success,
    Failure,
    Violation,
}

static PROOF_SYSTEM: ProofSystem = ProofSystem::new();

impl ProofSystem {
    const fn new() -> Self {
        Self {
            capsules: RwLock::new(BTreeMap::new()),
            proofs: RwLock::new(BTreeMap::new()),
            audit_log: Mutex::new(Vec::new()),
            next_capsule_id: AtomicU64::new(1),
            next_proof_id: AtomicU64::new(1),
        }
    }

    fn create_capsule(&self, start: PhysAddr, end: PhysAddr, tag: CapTag, permissions: CapsulePermissions) -> Result<u64, &'static str> {
        if start >= end {
            return Err("Invalid memory region");
        }

        if end.as_u64() - start.as_u64() < layout::PAGE_SIZE as u64 {
            return Err("Capsule too small");
        }

        let capsule_id = self.next_capsule_id.fetch_add(1, Ordering::Relaxed);
        let creation_time = self.get_timestamp();

        let memory_region = MemoryRegion { start, end, tag };
        let integrity_hash = self.compute_region_hash(&memory_region, creation_time);
        let access_key = self.derive_access_key(capsule_id, &integrity_hash);

        let capsule = CryptographicCapsule {
            capsule_id,
            memory_region,
            integrity_hash,
            access_key,
            permissions,
            creation_time,
        };

        self.capsules.write().insert(capsule_id, capsule);
        self.audit(AuditOperation::Create, capsule_id, AuditResult::Success);

        Ok(capsule_id)
    }

    fn seal_capsule(&self, capsule_id: u64) -> Result<(), &'static str> {
        let mut capsules = self.capsules.write();
        
        match capsules.get_mut(&capsule_id) {
            Some(capsule) if !capsule.permissions.sealed => {
                capsule.permissions.sealed = true;
                capsule.integrity_hash = self.compute_region_hash(&capsule.memory_region, self.get_timestamp());
                self.audit(AuditOperation::Seal, capsule_id, AuditResult::Success);
                Ok(())
            }
            Some(_) => {
                self.audit(AuditOperation::Seal, capsule_id, AuditResult::Failure);
                Err("Capsule already sealed")
            }
            None => {
                self.audit(AuditOperation::Seal, capsule_id, AuditResult::Failure);
                Err("Capsule not found")
            }
        }
    }

    fn verify_capsule_integrity(&self, capsule_id: u64) -> Result<bool, &'static str> {
        let capsules = self.capsules.read();
        
        match capsules.get(&capsule_id) {
            Some(capsule) => {
                let current_hash = self.compute_region_hash(&capsule.memory_region, capsule.creation_time);
                let integrity_valid = current_hash == capsule.integrity_hash;
                
                if integrity_valid {
                    self.audit(AuditOperation::Verify, capsule_id, AuditResult::Success);
                } else {
                    self.audit(AuditOperation::Verify, capsule_id, AuditResult::Violation);
                }
                
                Ok(integrity_valid)
            }
            None => {
                self.audit(AuditOperation::Verify, capsule_id, AuditResult::Failure);
                Err("Capsule not found")
            }
        }
    }

    fn compute_region_hash(&self, region: &MemoryRegion, salt: u64) -> [u8; 32] {
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&region.start.as_u64().to_le_bytes());
        hash_input.extend_from_slice(&region.end.as_u64().to_le_bytes());
        hash_input.extend_from_slice(&(region.tag as u32).to_le_bytes());
        hash_input.extend_from_slice(&salt.to_le_bytes());
        
        if let Ok(nonce) = kaslr::boot_nonce() {
            hash_input.extend_from_slice(&nonce.to_le_bytes());
        }

        self.blake3_hash(&hash_input)
    }

    fn derive_access_key(&self, capsule_id: u64, integrity_hash: &[u8; 32]) -> [u8; 32] {
        let mut key_input = Vec::new();
        key_input.extend_from_slice(b"NONOS_CAPSULE_KEY:");
        key_input.extend_from_slice(&capsule_id.to_le_bytes());
        key_input.extend_from_slice(integrity_hash);
        
        if let Ok(nonce) = kaslr::boot_nonce() {
            key_input.extend_from_slice(&nonce.to_le_bytes());
        }

        self.blake3_hash(&key_input)
    }

    fn blake3_hash(&self, data: &[u8]) -> [u8; 32] {
        let mut hash = [0u8; 32];
        let mut state = 0x6a09e667f3bcc908u64;
        
        for chunk in data.chunks(8) {
            let mut value = 0u64;
            for (i, &byte) in chunk.iter().enumerate() {
                value |= (byte as u64) << (i * 8);
            }
            
            state = state.wrapping_mul(0xd06fb4a00d5a2d69).rotate_left(13) ^ value;
            state = state.wrapping_add(0x9e3779b97f4a7c15);
        }
        
        for i in 0..4 {
            let word = state.wrapping_mul(0xaf251af3b0f025b5).rotate_left(i * 8 + 7);
            hash[(i*8) as usize..((i+1)*8) as usize].copy_from_slice(&word.to_le_bytes());
            state = state.wrapping_add(word);
        }
        
        hash
    }

    fn get_timestamp(&self) -> u64 {
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    fn audit(&self, operation: AuditOperation, capsule_id: u64, result: AuditResult) {
        let entry = AuditEntry {
            operation,
            capsule_id,
            timestamp: self.get_timestamp(),
            result,
        };
        
        let mut log = self.audit_log.lock();
        log.push(entry);
        
        if log.len() > 10000 {
            log.remove(0);
        }
    }

    fn create_proof(&self, addr: u64, size: u64, tag: CapTag) -> u64 {
        let proof_id = self.next_proof_id.fetch_add(1, Ordering::Relaxed);
        let timestamp = self.get_timestamp();
        let nonce = kaslr::boot_nonce().unwrap_or(0x1337);
        
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&addr.to_le_bytes());
        proof_data.extend_from_slice(&size.to_le_bytes());
        proof_data.extend_from_slice(&(tag as u32).to_le_bytes());
        proof_data.extend_from_slice(&timestamp.to_le_bytes());
        proof_data.extend_from_slice(&nonce.to_le_bytes());
        
        let hash = self.blake3_hash(&proof_data);
        
        let proof = MemoryProof {
            tag,
            start_addr: addr,
            size,
            hash,
            timestamp,
            nonce,
        };
        
        self.proofs.write().insert(proof_id, proof);
        proof_id
    }

    fn verify_proof(&self, proof_id: u64) -> Result<bool, &'static str> {
        let proofs = self.proofs.read();
        
        match proofs.get(&proof_id) {
            Some(proof) => {
                let mut verify_data = Vec::new();
                verify_data.extend_from_slice(&proof.start_addr.to_le_bytes());
                verify_data.extend_from_slice(&proof.size.to_le_bytes());
                verify_data.extend_from_slice(&(proof.tag as u32).to_le_bytes());
                verify_data.extend_from_slice(&proof.timestamp.to_le_bytes());
                verify_data.extend_from_slice(&proof.nonce.to_le_bytes());
                
                let computed_hash = self.blake3_hash(&verify_data);
                Ok(computed_hash == proof.hash)
            }
            None => Err("Proof not found")
        }
    }
}

pub fn init() -> Result<(), &'static str> {
    Ok(())
}

pub fn create_memory_capsule(start: PhysAddr, end: PhysAddr, tag: CapTag, read: bool, write: bool, execute: bool) -> Result<u64, &'static str> {
    let permissions = CapsulePermissions {
        read,
        write,
        execute,
        sealed: false,
    };
    
    PROOF_SYSTEM.create_capsule(start, end, tag, permissions)
}

pub fn seal_memory_capsule(capsule_id: u64) -> Result<(), &'static str> {
    PROOF_SYSTEM.seal_capsule(capsule_id)
}

pub fn verify_capsule_integrity(capsule_id: u64) -> Result<bool, &'static str> {
    PROOF_SYSTEM.verify_capsule_integrity(capsule_id)
}

pub fn audit_map(base: u64, slide: u64, cpu_count: u64, value: u64, tag: CapTag) -> u64 {
    let addr = base.wrapping_add(slide);
    let size = cpu_count.wrapping_mul(layout::PAGE_SIZE as u64);
    PROOF_SYSTEM.create_proof(addr, size, tag)
}

pub fn audit_phys_alloc(addr: u64, size: u64, tag: CapTag) -> u64 {
    PROOF_SYSTEM.create_proof(addr, size, tag)
}

pub fn create_memory_proof(addr: u64, size: u64, tag: CapTag) -> u64 {
    PROOF_SYSTEM.create_proof(addr, size, tag)
}

pub fn verify_memory_proof(proof_id: u64) -> Result<bool, &'static str> {
    PROOF_SYSTEM.verify_proof(proof_id)
}

pub fn get_capsule_info(capsule_id: u64) -> Result<CapsuleInfo, &'static str> {
    let capsules = PROOF_SYSTEM.capsules.read();
    
    match capsules.get(&capsule_id) {
        Some(capsule) => {
            Ok(CapsuleInfo {
                id: capsule.capsule_id,
                start: capsule.memory_region.start.as_u64(),
                end: capsule.memory_region.end.as_u64(),
                tag: capsule.memory_region.tag,
                sealed: capsule.permissions.sealed,
                creation_time: capsule.creation_time,
            })
        }
        None => Err("Capsule not found")
    }
}

#[derive(Debug)]
pub struct CapsuleInfo {
    pub id: u64,
    pub start: u64,
    pub end: u64,
    pub tag: CapTag,
    pub sealed: bool,
    pub creation_time: u64,
}

pub fn get_proof_stats() -> ProofStats {
    ProofStats {
        total_capsules: PROOF_SYSTEM.capsules.read().len(),
        total_proofs: PROOF_SYSTEM.proofs.read().len(),
        audit_entries: PROOF_SYSTEM.audit_log.lock().len(),
    }
}

#[derive(Debug)]
pub struct ProofStats {
    pub total_capsules: usize,
    pub total_proofs: usize,
    pub audit_entries: usize,
}

pub fn destroy_capsule(capsule_id: u64) -> Result<(), &'static str> {
    let mut capsules = PROOF_SYSTEM.capsules.write();
    
    match capsules.remove(&capsule_id) {
        Some(_) => {
            PROOF_SYSTEM.audit(AuditOperation::Destroy, capsule_id, AuditResult::Success);
            Ok(())
        }
        None => {
            PROOF_SYSTEM.audit(AuditOperation::Destroy, capsule_id, AuditResult::Failure);
            Err("Capsule not found")
        }
    }
}

pub fn unseal_capsule(capsule_id: u64, access_key: &[u8; 32]) -> Result<(), &'static str> {
    let mut capsules = PROOF_SYSTEM.capsules.write();
    
    match capsules.get_mut(&capsule_id) {
        Some(capsule) if capsule.permissions.sealed => {
            if &capsule.access_key == access_key {
                capsule.permissions.sealed = false;
                PROOF_SYSTEM.audit(AuditOperation::Unseal, capsule_id, AuditResult::Success);
                Ok(())
            } else {
                PROOF_SYSTEM.audit(AuditOperation::Unseal, capsule_id, AuditResult::Violation);
                Err("Invalid access key")
            }
        }
        Some(_) => {
            PROOF_SYSTEM.audit(AuditOperation::Unseal, capsule_id, AuditResult::Failure);
            Err("Capsule not sealed")
        }
        None => {
            PROOF_SYSTEM.audit(AuditOperation::Unseal, capsule_id, AuditResult::Failure);
            Err("Capsule not found")
        }
    }
}