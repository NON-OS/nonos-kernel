//! SHA-3 (Keccak) 
//! 
//! This is a complete, cryptographically secure implementation of SHA-3 and SHAKE
//! based on the FIPS 202 standard with the Keccak-f[1600] permutation.

extern crate alloc;
use alloc::vec::Vec;

/// Keccak round constants for the ι (iota) step
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    0x8000000000000000, 0x0000000080008082, 0x800000000000808a, 0x8000000080008000,
];

/// Rotation offsets for the ρ (rho) step
const RHO_OFFSETS: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
];

/// Lane indices for the π (pi) step
const PI_LANE: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
];

/// Keccak-f[1600] permutation - the core cryptographic function
fn keccak_f(state: &mut [u64; 25]) {
    for round in 0..24 {
        // θ (theta) step: Column parity computation
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        
        for x in 0..5 {
            for y in 0..5 {
                state[y * 5 + x] ^= d[x];
            }
        }
        
        // ρ (rho) and π (pi) steps combined
        let mut current = state[1];
        for i in 0..24 {
            let j = PI_LANE[i];
            let temp = state[j];
            state[j] = current.rotate_left(RHO_OFFSETS[i]);
            current = temp;
        }
        
        // χ (chi) step: Non-linear transformation
        for y in 0..5 {
            let t = [
                state[y * 5 + 0], state[y * 5 + 1], state[y * 5 + 2], 
                state[y * 5 + 3], state[y * 5 + 4]
            ];
            for x in 0..5 {
                state[y * 5 + x] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
            }
        }
        
        // ι (iota) step: Round constant addition
        state[0] ^= ROUND_CONSTANTS[round];
    }
}

/// Core Keccak sponge construction
pub struct Keccak {
    state: [u64; 25],
    buffer: Vec<u8>,
    rate: usize,
    capacity: usize,
    output_len: usize,
    suffix: u8,
}

impl Keccak {
    /// Create a new Keccak instance with specified parameters
    pub fn new(capacity: usize, output_len: usize, suffix: u8) -> Self {
        assert!(capacity <= 1600);
        assert!(capacity % 8 == 0);
        
        Self {
            state: [0u64; 25],
            buffer: Vec::new(),
            rate: (1600 - capacity) / 8,
            capacity,
            output_len,
            suffix,
        }
    }
    
    /// Update the sponge with input data
    pub fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }
    
    /// Absorb phase: process input into the sponge
    fn absorb(&mut self) {
        // Pad the message according to the padding rule
        self.buffer.push(self.suffix);
        
        // Pad to rate boundary
        while self.buffer.len() % self.rate != 0 {
            self.buffer.push(0);
        }
        
        // Set the last bit of the last byte (10*1 padding completion)
        if let Some(last) = self.buffer.last_mut() {
            *last |= 0x80;
        }
        
        // Process each rate-sized block
        for chunk in self.buffer.chunks_exact(self.rate) {
            // XOR the chunk into the state
            for (i, &byte) in chunk.iter().enumerate() {
                let lane_idx = i / 8;
                let byte_idx = i % 8;
                let byte_shift = byte_idx * 8;
                self.state[lane_idx] ^= (byte as u64) << byte_shift;
            }
            
            // Apply the permutation
            keccak_f(&mut self.state);
        }
    }
    
    /// Squeeze phase: extract output from the sponge
    fn squeeze(&mut self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.output_len);
        let mut remaining = self.output_len;
        
        while remaining > 0 {
            // Extract bytes from current state
            let to_extract = core::cmp::min(remaining, self.rate);
            
            for i in 0..to_extract {
                let lane_idx = i / 8;
                let byte_idx = i % 8;
                let byte = (self.state[lane_idx] >> (byte_idx * 8)) as u8;
                output.push(byte);
            }
            
            remaining -= to_extract;
            
            // If we need more output, apply permutation and continue
            if remaining > 0 {
                keccak_f(&mut self.state);
            }
        }
        
        output
    }
    
    /// Finalize and return the hash
    pub fn finalize(mut self) -> Vec<u8> {
        self.absorb();
        self.squeeze()
    }
}

/// SHA-3-256 hasher
pub struct Sha3_256 {
    keccak: Keccak,
}

impl Sha3_256 {
    /// Create a new SHA-3-256 hasher
    pub fn new() -> Self {
        Self {
            keccak: Keccak::new(512, 32, 0x06), // SHA-3 uses 0x06 suffix
        }
    }
    
    /// Update with input data
    pub fn update(&mut self, data: &[u8]) {
        self.keccak.update(data);
    }
    
    /// Finalize and return 32-byte hash
    pub fn finalize(self) -> [u8; 32] {
        let result = self.keccak.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// One-shot hash function
    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// SHA-3-512 hasher
pub struct Sha3_512 {
    keccak: Keccak,
}

impl Sha3_512 {
    pub fn new() -> Self {
        Self {
            keccak: Keccak::new(1024, 64, 0x06),
        }
    }
    
    pub fn update(&mut self, data: &[u8]) {
        self.keccak.update(data);
    }
    
    pub fn finalize(self) -> [u8; 64] {
        let result = self.keccak.finalize();
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&result);
        hash
    }
    
    pub fn digest(data: &[u8]) -> [u8; 64] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// SHAKE-128 extendable output function
pub struct Shake128 {
    keccak: Keccak,
}

impl Shake128 {
    pub fn new() -> Self {
        Self {
            keccak: Keccak::new(256, 0, 0x1f), // SHAKE uses 0x1f suffix
        }
    }
    
    pub fn update(&mut self, data: &[u8]) {
        self.keccak.update(data);
    }
    
    /// Finalize and return specified number of output bytes
    pub fn finalize(mut self, output_len: usize) -> Vec<u8> {
        self.keccak.output_len = output_len;
        self.keccak.finalize()
    }
    
    /// One-shot SHAKE-128
    pub fn digest(data: &[u8], output_len: usize) -> Vec<u8> {
        let mut shake = Self::new();
        shake.update(data);
        shake.finalize(output_len)
    }
}

/// SHAKE-256 extendable output function  
pub struct Shake256 {
    keccak: Keccak,
}

impl Shake256 {
    pub fn new() -> Self {
        Self {
            keccak: Keccak::new(512, 0, 0x1f),
        }
    }
    
    pub fn update(&mut self, data: &[u8]) {
        self.keccak.update(data);
    }
    
    pub fn finalize(mut self, output_len: usize) -> Vec<u8> {
        self.keccak.output_len = output_len;
        self.keccak.finalize()
    }
    
    pub fn digest(data: &[u8], output_len: usize) -> Vec<u8> {
        let mut shake = Self::new();
        shake.update(data);
        shake.finalize(output_len)
    }
}

/// Convenience functions
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data)
}

pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    Sha3_512::digest(data)
}

pub fn shake128(data: &[u8], output_len: usize) -> Vec<u8> {
    Shake128::digest(data, output_len)
}

pub fn shake256(data: &[u8], output_len: usize) -> Vec<u8> {
    Shake256::digest(data, output_len)
}

impl Default for Sha3_256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Sha3_512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sha3_256_empty() {
        let hash = sha3_256(b"");
        // Known test vector for empty string
        let expected = [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
            0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
            0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
            0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
        ];
        assert_eq!(hash, expected);
    }
    
    #[test]
    fn test_sha3_256_abc() {
        let hash = sha3_256(b"abc");
        // Known test vector for "abc"
        let expected = [
            0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
            0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
            0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
            0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
        ];
        assert_eq!(hash, expected);
    }
}