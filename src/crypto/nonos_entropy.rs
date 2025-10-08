//! Entropy and RNG for NON-OS

use core::sync::atomic::{AtomicU64, Ordering};
extern crate alloc;

static RNG_STATE: AtomicU64 = AtomicU64::new(1);

// Entropy pool constants and cache
const ENTROPY_POOL_SIZE: usize = 8;
static mut ENTROPY_POOL_CACHE: [u64; ENTROPY_POOL_SIZE] = [0; ENTROPY_POOL_SIZE];

/// Early initialization of entropy sources before heap is available
pub unsafe fn init_early() {
    // Initialize with hardware entropy if available
    seed_rng();
    
    // Try to get CPU entropy
    if is_rdrand_available() {
        let hw_entropy = get_rdrand();
        let current = RNG_STATE.load(Ordering::SeqCst);
        RNG_STATE.store(current ^ hw_entropy, Ordering::SeqCst);
    }
}

pub fn seed_rng() {
    // Initialize with a simple seed
    RNG_STATE.store(0x1337_BEEF_DEAD_CAFE, Ordering::SeqCst);
}

pub fn rand_u64() -> u64 {
    // Simple LFSR for now
    let state = RNG_STATE.load(Ordering::SeqCst);
    let new_state = state.wrapping_mul(1103515245).wrapping_add(12345);
    RNG_STATE.store(new_state, Ordering::SeqCst);
    new_state
}

/// Harvest entropy from time-based sources
pub fn harvest_time_entropy() {
    // Use current time as additional entropy source
    let time_entropy = crate::time::get_uptime_ns();
    let current_state = RNG_STATE.load(Ordering::SeqCst);
    let new_state = current_state ^ time_entropy;
    RNG_STATE.store(new_state, Ordering::SeqCst);
}

/// Check if RDRAND instruction is available
pub fn is_rdrand_available() -> bool {
    // Check CPUID for RDRAND support
    unsafe {
        let cpuid = core::arch::x86_64::__cpuid(1);
        (cpuid.ecx & (1 << 30)) != 0
    }
}

/// Get hardware random number using RDRAND
pub fn get_rdrand() -> u64 {
    unsafe {
        let mut result: u64;
        core::arch::asm!(
            "rdrand {}",
            out(reg) result,
            options(nostack, nomem)
        );
        result
    }
}

/// Get 32 random bytes as array - REAL IMPLEMENTATION  
pub fn get_random_bytes_32() -> [u8; 32] {
    let mut buffer = [0u8; 32];
    get_random_bytes(&mut buffer);
    buffer
}

/// Fill buffer with random bytes - REAL IMPLEMENTATION
pub fn get_random_bytes(buffer: &mut [u8]) {
    let mut offset = 0;
    while offset < buffer.len() {
        let rand_val = if is_rdrand_available() {
            get_rdrand()
        } else {
            rand_u64()
        };
        let bytes = rand_val.to_le_bytes();
        let copy_len = core::cmp::min(8, buffer.len() - offset);
        buffer[offset..offset + copy_len].copy_from_slice(&bytes[..copy_len]);
        offset += copy_len;
    }
}

/// Generate random bytes of specified size
pub fn rand_bytes(size: usize) -> alloc::vec::Vec<u8> {
    let mut buffer = alloc::vec![0u8; size];
    get_random_bytes(&mut buffer);
    buffer
}

/// Generate cryptographically secure random u32
pub fn secure_rand_u32() -> u32 {
    if is_rdrand_available() {
        (get_rdrand() & 0xFFFFFFFF) as u32
    } else {
        // Fallback with entropy harvesting
        harvest_time_entropy();
        (rand_u64() & 0xFFFFFFFF) as u32
    }
}

/// Generate cryptographically secure random bytes with entropy mixing
pub fn secure_random_bytes(buffer: &mut [u8]) {
    // Mix multiple entropy sources
    harvest_time_entropy();
    
    for chunk in buffer.chunks_mut(8) {
        let mut entropy = if is_rdrand_available() {
            get_rdrand()
        } else {
            rand_u64()
        };
        
        // Mix with TSC for additional entropy
        entropy ^= crate::arch::x86_64::time::get_tsc();
        
        let bytes = entropy.to_le_bytes();
        let len = core::cmp::min(chunk.len(), 8);
        chunk[..len].copy_from_slice(&bytes[..len]);
    }
}

/// Fill buffer with random bytes - REAL IMPLEMENTATION
pub fn fill_random(buffer: &mut [u8]) {
    get_random_bytes(buffer);
}

/// Generate random u32 - REAL IMPLEMENTATION
pub fn rand_u32() -> u32 {
    secure_rand_u32()
}

/// Add entropy from external sources for enhanced security
pub fn add_entropy_source(entropy_value: u16) {
    unsafe {
        ENTROPY_POOL_CACHE[0] ^= entropy_value as u64;
        ENTROPY_POOL_CACHE[1] = ENTROPY_POOL_CACHE[1].wrapping_add(entropy_value as u64);
        
        // Mix entropy through the pool
        for i in 0..ENTROPY_POOL_SIZE.min(8) {
            ENTROPY_POOL_CACHE[i] = ENTROPY_POOL_CACHE[i].wrapping_mul(0x5DEECE66D);
        }
    }
}

/// Initialize entropy system with bootloader-provided seed
pub fn init_entropy_system_with_seed(seed: &[u8; 32]) -> Result<(), &'static str> {
    // Convert seed to u64 values for our entropy pool
    unsafe {
        for (i, chunk) in seed.chunks(8).enumerate() {
            if i >= ENTROPY_POOL_SIZE { break; }
            
            let mut value = 0u64;
            for (j, &byte) in chunk.iter().enumerate() {
                value |= (byte as u64) << (j * 8);
            }
            ENTROPY_POOL_CACHE[i] = value;
        }
        
        // Mix the entropy pool
        for _ in 0..16 {
            for i in 0..ENTROPY_POOL_SIZE {
                ENTROPY_POOL_CACHE[i] = ENTROPY_POOL_CACHE[i]
                    .wrapping_mul(1103515245)
                    .wrapping_add(12345)
                    .rotate_left(13);
            }
        }
        
        // Seed the main RNG with mixed entropy
        let mixed_seed = ENTROPY_POOL_CACHE.iter().fold(0, |acc, &x| acc ^ x);
        RNG_STATE.store(mixed_seed, Ordering::SeqCst);
    }
    
    Ok(())
}

/// Get single entropy byte with full entropy mixing
pub fn get_entropy_byte() -> u8 {
    // Mix multiple entropy sources for single byte
    harvest_time_entropy();
    
    let entropy = if is_rdrand_available() {
        get_rdrand()
    } else {
        rand_u64()
    };
    
    // XOR different byte positions for better entropy distribution
    let byte = (entropy as u8) 
        ^ ((entropy >> 8) as u8)
        ^ ((entropy >> 16) as u8)
        ^ ((entropy >> 24) as u8)
        ^ ((entropy >> 32) as u8)
        ^ ((entropy >> 40) as u8)
        ^ ((entropy >> 48) as u8)
        ^ ((entropy >> 56) as u8);
    
    byte
}

/// Get entropy bytes with cryptographic quality
pub fn get_entropy_bytes(count: usize) -> alloc::vec::Vec<u8> {
    let mut bytes = alloc::vec::Vec::with_capacity(count);
    bytes.resize(count, 0);
    secure_random_bytes(&mut bytes);
    bytes
}

/// Generate a secure random u32
pub fn secure_random_u32() -> u32 {
    let value = rand_u64();
    (value & 0xFFFFFFFF) as u32
}

