use core::sync::atomic::{AtomicU64, Ordering};

static GLOBAL_COUNTER: AtomicU64 = AtomicU64::new(1);
static mut RNG_STATE: [u32; 4] = [0x9E3779B9, 0x243F6A88, 0xB7E15162, 0x8AED2A6A];

/// ChaCha20-based RNG state
pub struct ChaChaRng {
    state: [u32; 16],
    output: [u32; 16],
    index: usize,
}

impl ChaChaRng {
    pub fn new(seed: u64) -> Self {
        let mut rng = Self {
            state: [0; 16],
            output: [0; 16],
            index: 16,
        };
        
        // ChaCha20 constants
        rng.state[0] = 0x61707865;
        rng.state[1] = 0x3320646e;
        rng.state[2] = 0x79622d32;
        rng.state[3] = 0x6b206574;
        
        // Key from seed
        rng.state[4] = seed as u32;
        rng.state[5] = (seed >> 32) as u32;
        rng.state[6] = (!seed) as u32;
        rng.state[7] = ((!seed) >> 32) as u32;
        rng.state[8] = seed.wrapping_mul(0x9E3779B97F4A7C15) as u32;
        rng.state[9] = (seed.wrapping_mul(0x9E3779B97F4A7C15) >> 32) as u32;
        rng.state[10] = seed.wrapping_add(0xA0761D6478BD642F) as u32;
        rng.state[11] = (seed.wrapping_add(0xA0761D6478BD642F) >> 32) as u32;
        
        // Counter and nonce
        rng.state[12] = 0;
        rng.state[13] = 0;
        rng.state[14] = 0;
        rng.state[15] = 0;
        
        rng
    }
    
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
    
    fn generate_block(&mut self) {
        let mut working_state = self.state;
        
        // 20 rounds (10 double rounds)
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
            self.output[i] = working_state[i].wrapping_add(self.state[i]);
        }
        
        // Increment counter
        self.state[12] = self.state[12].wrapping_add(1);
        if self.state[12] == 0 {
            self.state[13] = self.state[13].wrapping_add(1);
        }
        
        self.index = 0;
    }
    
    pub fn next_u32(&mut self) -> u32 {
        if self.index >= 16 {
            self.generate_block();
        }
        
        let result = self.output[self.index];
        self.index += 1;
        result
    }
    
    pub fn next_u64(&mut self) -> u64 {
        let low = self.next_u32() as u64;
        let high = self.next_u32() as u64;
        (high << 32) | low
    }
    
    pub fn fill_bytes(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(4) {
            let val = self.next_u32();
            let val_bytes = val.to_le_bytes();
            for (i, &byte) in val_bytes.iter().enumerate() {
                if i < chunk.len() {
                    chunk[i] = byte;
                }
            }
        }
    }
}

/// Simple xorshift64 for quick random numbers
fn xorshift64(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Get entropy from hardware sources
fn get_entropy() -> u64 {
    let mut entropy = 0u64;
    
    // Use atomic counter as basic entropy
    entropy ^= GLOBAL_COUNTER.fetch_add(1, Ordering::SeqCst);
    
    // Mix in some hardware-based entropy if available
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Try to use RDTSC
        let mut eax: u32;
        let mut edx: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") eax,
            out("edx") edx,
            options(nomem, nostack)
        );
        entropy ^= (eax as u64) | ((edx as u64) << 32);
    }
    
    // Add some memory address entropy
    let stack_addr = &entropy as *const u64 as u64;
    entropy ^= stack_addr;
    
    entropy
}

/// Initialize RNG system
pub fn init_rng() {
    let seed = get_entropy();
    unsafe {
        RNG_STATE[0] = seed as u32;
        RNG_STATE[1] = (seed >> 32) as u32;
        RNG_STATE[2] = (!seed) as u32;
        RNG_STATE[3] = ((!seed) >> 32) as u32;
    }
}

/// Seed the global RNG
pub fn seed_rng() {
    init_rng();
}

/// Get random bytes using global RNG
pub fn get_random_bytes() -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut rng_state = get_entropy();
    
    for chunk in result.chunks_mut(8) {
        let val = xorshift64(&mut rng_state);
        let bytes = val.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    
    result
}

/// Fill buffer with random bytes
pub fn fill_random_bytes(buffer: &mut [u8]) {
    let mut rng_state = get_entropy();
    
    for chunk in buffer.chunks_mut(8) {
        let val = xorshift64(&mut rng_state);
        let bytes = val.to_le_bytes();
        for (i, &byte) in bytes.iter().enumerate() {
            if i < chunk.len() {
                chunk[i] = byte;
            }
        }
    }
}

/// Generate a random u64
pub fn random_u64() -> u64 {
    let mut rng_state = get_entropy();
    xorshift64(&mut rng_state)
}

/// Generate a random u32
pub fn random_u32() -> u32 {
    random_u64() as u32
}