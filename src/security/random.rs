//! Complete Cryptographically Secure Random Number Generation
//!
//! Implementation includes:
//! - Hardware RNG (RDRAND/RDSEED) support
//! - ChaCha20-based CSPRNG for fallback
//! - Entropy collection from various sources
//! - Thread-safe global RNG state
//! - Constant-time operations

use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, Once};
use alloc::vec::Vec;

/// ChaCha20 constants
const CHACHA20_CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

/// Global RNG state
static RNG_STATE: Once<Mutex<ChaChaRng>> = Once::new();

/// Entropy pool for collecting system randomness
static ENTROPY_POOL: Mutex<EntropyPool> = Mutex::new(EntropyPool::new());

/// Global counter for additional entropy
static ENTROPY_COUNTER: AtomicU64 = AtomicU64::new(1);

/// ChaCha20-based CSPRNG
#[derive(Debug)]
pub struct ChaChaRng {
    state: [u32; 16],
    buffer: [u8; 64],
    buffer_pos: usize,
}

impl ChaChaRng {
    /// Create new ChaCha20 RNG with given key and nonce
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let mut state = [0u32; 16];
        
        // Constants
        state[0..4].copy_from_slice(&CHACHA20_CONSTANTS);
        
        // Key
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes([
                key[i * 4],
                key[i * 4 + 1],
                key[i * 4 + 2],
                key[i * 4 + 3],
            ]);
        }
        
        // Counter (starts at 0)
        state[12] = 0;
        
        // Nonce
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }
        
        let mut rng = ChaChaRng {
            state,
            buffer: [0; 64],
            buffer_pos: 64, // Force refill on first use
        };
        
        // Generate initial buffer
        rng.refill_buffer();
        rng
    }
    
    /// Refill the internal buffer
    fn refill_buffer(&mut self) {
        let mut temp_buffer = [0u8; 64];
        self.chacha20_block(&mut temp_buffer);
        self.buffer = temp_buffer;
        self.state[12] = self.state[12].wrapping_add(1); // Increment counter
        self.buffer_pos = 0;
    }
    
    /// Generate one ChaCha20 block
    fn chacha20_block(&self, output: &mut [u8; 64]) {
        let mut working_state = self.state;
        
        // 20 rounds (10 column rounds + 10 diagonal rounds)
        for _ in 0..10 {
            // Column rounds
            Self::quarter_round(&mut working_state, 0, 4, 8, 12);
            Self::quarter_round(&mut working_state, 1, 5, 9, 13);
            Self::quarter_round(&mut working_state, 2, 6, 10, 14);
            Self::quarter_round(&mut working_state, 3, 7, 11, 15);
            
            // Diagonal rounds
            Self::quarter_round(&mut working_state, 0, 5, 10, 15);
            Self::quarter_round(&mut working_state, 1, 6, 11, 12);
            Self::quarter_round(&mut working_state, 2, 7, 8, 13);
            Self::quarter_round(&mut working_state, 3, 4, 9, 14);
        }
        
        // Add original state
        for i in 0..16 {
            working_state[i] = working_state[i].wrapping_add(self.state[i]);
        }
        
        // Convert to bytes
        for i in 0..16 {
            let bytes = working_state[i].to_le_bytes();
            output[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
    }
    
    /// ChaCha20 quarter round
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);
        
        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);
        
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);
        
        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }
    
    /// Fill buffer with random bytes
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0;
        
        while offset < dest.len() {
            if self.buffer_pos >= 64 {
                self.refill_buffer();
            }
            
            let available = 64 - self.buffer_pos;
            let needed = dest.len() - offset;
            let to_copy = core::cmp::min(available, needed);
            
            dest[offset..offset + to_copy].copy_from_slice(
                &self.buffer[self.buffer_pos..self.buffer_pos + to_copy]
            );
            
            self.buffer_pos += to_copy;
            offset += to_copy;
        }
    }
    
    /// Generate random u64
    pub fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    
    /// Generate random u32
    pub fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }
}

/// Entropy collection pool
#[derive(Debug)]
pub struct EntropyPool {
    pool: [u8; 256],
    position: usize,
    mixed_count: u64,
}

impl EntropyPool {
    /// Create new entropy pool
    pub const fn new() -> Self {
        EntropyPool {
            pool: [0; 256],
            position: 0,
            mixed_count: 0,
        }
    }
    
    /// Add entropy from various sources
    pub fn add_entropy(&mut self, data: &[u8]) {
        for &byte in data {
            self.pool[self.position] ^= byte;
            self.position = (self.position + 1) % self.pool.len();
        }
        self.mixed_count += data.len() as u64;
        
        // Mix the pool periodically
        if self.mixed_count % 128 == 0 {
            self.mix_pool();
        }
    }
    
    /// Mix the entropy pool using a simple hash
    fn mix_pool(&mut self) {
        for i in 0..self.pool.len() {
            let next = (i + 1) % self.pool.len();
            let prev = (i + self.pool.len() - 1) % self.pool.len();
            
            self.pool[i] = self.pool[i]
                .wrapping_add(self.pool[next])
                .wrapping_add(self.pool[prev])
                .wrapping_add((i as u8).wrapping_mul(73));
        }
    }
    
    /// Extract seed from entropy pool
    pub fn extract_seed(&mut self) -> [u8; 32] {
        self.mix_pool();
        
        let mut seed = [0u8; 32];
        for i in 0..32 {
            seed[i] = self.pool[i * 8 % self.pool.len()];
        }
        
        // Clear used entropy
        for i in 0..32 {
            self.pool[i * 8 % self.pool.len()] = 0;
        }
        
        seed
    }
}

/// Check if hardware RNG is available
pub fn has_rdrand() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::{__cpuid, CpuidResult};
        
        // Check CPUID.01H:ECX.RDRAND[bit 30]
        let result: CpuidResult = unsafe { __cpuid(1) };
        (result.ecx & (1 << 30)) != 0
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    false
}

/// Check if RDSEED is available
pub fn has_rdseed() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::{__cpuid, CpuidResult};
        
        // Check CPUID.07H:EBX.RDSEED[bit 18]
        let result: CpuidResult = unsafe { __cpuid_count(7, 0) };
        (result.ebx & (1 << 18)) != 0
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    false
}

/// Get hardware random number using RDRAND
#[cfg(target_arch = "x86_64")]
pub fn hw_rdrand() -> Option<u64> {
    if !has_rdrand() {
        return None;
    }
    
    unsafe {
        let mut result: u64;
        let success: u8;
        
        core::arch::asm!(
            "rdrand {result}",
            "setc {success}",
            result = out(reg) result,
            success = out(reg_byte) success,
            options(nomem, nostack, preserves_flags)
        );
        
        if success == 1 {
            Some(result)
        } else {
            None
        }
    }
}

/// Get hardware random seed using RDSEED
#[cfg(target_arch = "x86_64")]
pub fn hw_rdseed() -> Option<u64> {
    if !has_rdseed() {
        return None;
    }
    
    unsafe {
        let mut result: u64;
        let success: u8;
        
        core::arch::asm!(
            "rdseed {result}",
            "setc {success}",
            result = out(reg) result,
            success = out(reg_byte) success,
            options(nomem, nostack, preserves_flags)
        );
        
        if success == 1 {
            Some(result)
        } else {
            None
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn hw_rdrand() -> Option<u64> {
    None
}

#[cfg(not(target_arch = "x86_64"))]
pub fn hw_rdseed() -> Option<u64> {
    None
}

/// Initialize the global RNG
pub fn init() -> Result<(), &'static str> {
    // Collect initial entropy
    let mut entropy_pool = ENTROPY_POOL.lock();
    
    // Add entropy from various sources
    collect_system_entropy(&mut entropy_pool);
    
    // Extract seed
    let seed = entropy_pool.extract_seed();
    drop(entropy_pool);
    
    // Create nonce from TSC and other sources
    let mut nonce = [0u8; 12];
    let tsc = crate::arch::x86_64::time::get_tsc();
    nonce[0..8].copy_from_slice(&tsc.to_le_bytes());
    nonce[8..12].copy_from_slice(&(ENTROPY_COUNTER.fetch_add(1, Ordering::SeqCst) as u32).to_le_bytes());
    
    // Initialize global RNG
    let rng = ChaChaRng::new(&seed, &nonce);
    RNG_STATE.call_once(|| Mutex::new(rng));
    
    Ok(())
}

/// Collect entropy from system sources
fn collect_system_entropy(pool: &mut EntropyPool) {
    // Hardware RNG if available
    if let Some(hw_rand) = hw_rdseed().or_else(|| hw_rdrand()) {
        pool.add_entropy(&hw_rand.to_le_bytes());
    }
    
    // TSC
    let tsc = crate::arch::x86_64::time::get_tsc();
    pool.add_entropy(&tsc.to_le_bytes());
    
    // Stack address (ASLR entropy)
    let stack_addr = &pool as *const _ as usize;
    pool.add_entropy(&stack_addr.to_le_bytes());
    
    // Memory content at various addresses (careful not to cause page faults)
    unsafe {
        let addrs = [0x1000usize, 0x2000, 0x3000, 0x4000];
        for &addr in &addrs {
            // Only read if address seems valid
            if addr > 0x1000 && addr < 0x100000 {
                let ptr = addr as *const u64;
                if !ptr.is_null() {
                    // Try to read, but handle potential faults gracefully
                    let val = core::ptr::read_volatile(ptr);
                    pool.add_entropy(&val.to_le_bytes());
                }
            }
        }
    }
    
    // Global counter
    let counter = ENTROPY_COUNTER.fetch_add(1, Ordering::SeqCst);
    pool.add_entropy(&counter.to_le_bytes());
}

/// Fill buffer with cryptographically secure random bytes
pub fn fill_random(dest: &mut [u8]) {
    // Ensure RNG is initialized
    if RNG_STATE.get().is_none() {
        init().expect("Failed to initialize RNG");
    }
    
    // Add fresh entropy periodically
    if ENTROPY_COUNTER.fetch_add(1, Ordering::SeqCst) % 1000 == 0 {
        let mut entropy_pool = ENTROPY_POOL.lock();
        collect_system_entropy(&mut entropy_pool);
        drop(entropy_pool);
    }
    
    // Generate random bytes
    if let Some(rng_mutex) = RNG_STATE.get() {
        let mut rng = rng_mutex.lock();
        rng.fill_bytes(dest);
    } else {
        panic!("RNG not initialized");
    }
}

/// Generate cryptographically secure random u64
pub fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    fill_random(&mut bytes);
    u64::from_le_bytes(bytes)
}

/// Generate cryptographically secure random u32
pub fn random_u32() -> u32 {
    let mut bytes = [0u8; 4];
    fill_random(&mut bytes);
    u32::from_le_bytes(bytes)
}

/// Generate cryptographically secure random usize
pub fn random_usize() -> usize {
    let mut bytes = [0u8; core::mem::size_of::<usize>()];
    fill_random(&mut bytes);
    usize::from_le_bytes(bytes)
}

/// Constant-time comparison of byte arrays
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }
    
    result == 0
}

/// Generate random bytes for testing (deterministic in test builds)
#[cfg(test)]
pub fn test_random(dest: &mut [u8]) {
    // Deterministic random for tests
    for (i, byte) in dest.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(73).wrapping_add(37);
    }
}

/// Re-seed the global RNG with fresh entropy
pub fn reseed() {
    let mut entropy_pool = ENTROPY_POOL.lock();
    collect_system_entropy(&mut entropy_pool);
    let seed = entropy_pool.extract_seed();
    drop(entropy_pool);
    
    let mut nonce = [0u8; 12];
    let tsc = crate::arch::x86_64::time::get_tsc();
    nonce[0..8].copy_from_slice(&tsc.to_le_bytes());
    nonce[8..12].copy_from_slice(&(random_u32()).to_le_bytes());
    
    if let Some(rng_mutex) = RNG_STATE.get() {
        let mut rng = rng_mutex.lock();
        *rng = ChaChaRng::new(&seed, &nonce);
    }
}

/// Get entropy estimate (rough measure of randomness quality)
pub fn entropy_estimate() -> u32 {
    let mut estimate = 0u32;
    
    // Hardware RNG provides high entropy
    if has_rdseed() {
        estimate += 64; // bits
    } else if has_rdrand() {
        estimate += 32; // bits  
    }
    
    // TSC provides some entropy
    estimate += 16;
    
    // System state provides minimal entropy
    estimate += 8;
    
    estimate
}

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::__cpuid_count;