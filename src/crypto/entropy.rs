//! Entropy gathering for cryptographic operations

#![no_std]

extern crate alloc;
use alloc::vec::Vec;
use core::arch::x86_64::{_rdtsc, __cpuid};
use super::rng::{get_random_bytes, fill_random_bytes};
use super::hash::sha256;

/// Hardware entropy sources
struct EntropySource {
    rdrand_available: bool,
    rdseed_available: bool,
}

static mut ENTROPY_SOURCE: EntropySource = EntropySource {
    rdrand_available: false,
    rdseed_available: false,
};

/// Initialize entropy subsystem
pub fn init() {
    unsafe {
        // Check CPUID for RDRAND (bit 30 of ECX in leaf 1)
        let cpuid = __cpuid(1);
        ENTROPY_SOURCE.rdrand_available = (cpuid.ecx & (1 << 30)) != 0;
        
        // Check CPUID for RDSEED (bit 18 of EBX in leaf 7, subleaf 0)
        let cpuid_ext = __cpuid_count(7, 0);
        ENTROPY_SOURCE.rdseed_available = (cpuid_ext.ebx & (1 << 18)) != 0;
    }
}

/// Get hardware random using RDRAND instruction
fn rdrand64() -> Option<u64> {
    unsafe {
        if !ENTROPY_SOURCE.rdrand_available {
            return None;
        }
        
        let mut val: u64;
        let mut success: u8;
        
        core::arch::asm!(
            "rdrand {val}",
            "setc {success}",
            val = out(reg) val,
            success = out(reg_byte) success,
            options(nomem, nostack, preserves_flags)
        );
        
        if success != 0 {
            Some(val)
        } else {
            None
        }
    }
}

/// Get hardware random using RDSEED instruction
fn rdseed64() -> Option<u64> {
    unsafe {
        if !ENTROPY_SOURCE.rdseed_available {
            return None;
        }
        
        let mut val: u64;
        let mut success: u8;
        
        core::arch::asm!(
            "rdseed {val}",
            "setc {success}",
            val = out(reg) val,
            success = out(reg_byte) success,
            options(nomem, nostack, preserves_flags)
        );
        
        if success != 0 {
            Some(val)
        } else {
            None
        }
    }
}

/// Collect entropy from multiple hardware sources
pub fn gather_entropy() -> [u8; 32] {
    let mut entropy = [0u8; 32];
    let mut offset = 0;
    
    // Use RDSEED if available 
    for _ in 0..4 {
        if let Some(val) = rdseed64() {
            if offset + 8 <= entropy.len() {
                entropy[offset..offset + 8].copy_from_slice(&val.to_ne_bytes());
                offset += 8;
            }
        }
    }
    
    // Fill remaining with RDRAND (PRNG)
    while offset < entropy.len() {
        if let Some(val) = rdrand64() {
            let remaining = entropy.len() - offset;
            let copy_len = core::cmp::min(8, remaining);
            entropy[offset..offset + copy_len].copy_from_slice(&val.to_ne_bytes()[..copy_len]);
            offset += copy_len;
        } else {
            break;
        }
    }
    
    // If hardware unavailable, use system sources
    if offset == 0 {
        fill_random_bytes(&mut entropy);
        return entropy;
    }
    
    // Mix with TSC and hash for additional entropy
    unsafe {
        let tsc = _rdtsc();
        let timestamp = crate::time::timestamp_millis();
        
        let mut mixer = Vec::with_capacity(entropy.len() + 16);
        mixer.extend_from_slice(&entropy);
        mixer.extend_from_slice(&tsc.to_ne_bytes());
        mixer.extend_from_slice(&timestamp.to_ne_bytes());
        
        let hash = sha256(&mixer);
        entropy.copy_from_slice(&hash);
    }
    
    entropy
}

/// Get entropy bytes
pub fn get_entropy(len: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(len);
    let mut filled = 0;
    
    while filled < len {
        let chunk = gather_entropy();
        let remaining = len - filled;
        let copy_len = core::cmp::min(chunk.len(), remaining);
        
        result.extend_from_slice(&chunk[..copy_len]);
        filled += copy_len;
    }
    
    result
}

/// Fill buffer with high-quality entropy
pub fn fill_entropy(buf: &mut [u8]) {
    let mut offset = 0;
    
    while offset < buf.len() {
        let chunk = gather_entropy();
        let remaining = buf.len() - offset;
        let copy_len = core::cmp::min(chunk.len(), remaining);
        
        buf[offset..offset + copy_len].copy_from_slice(&chunk[..copy_len]);
        offset += copy_len;
    }
}

/// Get single random u64 with hardware entropy
pub fn get_random_u64() -> u64 {
    if let Some(val) = rdseed64() {
        val
    } else if let Some(val) = rdrand64() {
        val
    } else {
        let bytes = get_random_bytes();
        u64::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]])
    }
}

/// Check if hardware RNG is available
pub fn has_hardware_rng() -> bool {
    unsafe {
        ENTROPY_SOURCE.rdrand_available || ENTROPY_SOURCE.rdseed_available
    }
}

#[allow(dead_code)]
unsafe fn __cpuid_count(leaf: u32, subleaf: u32) -> core::arch::x86_64::CpuidResult {
    let mut eax: u32;
    let mut ebx: u32;
    let mut ecx: u32;
    let mut edx: u32;
    
    core::arch::asm!(
        "mov {ebx}, rbx",
        "cpuid",
        "xchg {ebx}, rbx",
        inout("eax") leaf => eax,
        inout("ecx") subleaf => ecx,
        out("edx") edx,
        ebx = out(reg) ebx,
        options(nomem, nostack, preserves_flags)
    );
    
    core::arch::x86_64::CpuidResult { eax, ebx, ecx, edx }
}
pub fn fill_random(buffer: &mut [u8]) -> Result<(), &'static str> {
    let entropy = get_entropy(buffer.len());
    buffer.copy_from_slice(&entropy[..buffer.len()]);
    Ok(())
}

pub fn rand_u32() -> u32 {
    let entropy = get_entropy(4);
    u32::from_le_bytes([entropy[0], entropy[1], entropy[2], entropy[3]])
}

pub fn rand_u64() -> u64 {
    let entropy = get_entropy(8);
    u64::from_le_bytes([entropy[0], entropy[1], entropy[2], entropy[3], entropy[4], entropy[5], entropy[6], entropy[7]])
}
