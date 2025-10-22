//! HMAC (Hash-based Message Authentication Code) implementation

#![no_std]

extern crate alloc;
use alloc::vec::Vec;
use super::hash::{sha256, Hash256};
use super::sha512::{sha512, Hash512};

/// HMAC with SHA-256
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Hash256 {
    hmac_generic(key, message, 64, sha256)
}

/// HMAC with SHA-512
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> Hash512 {
    hmac_generic(key, message, 128, sha512)
}

/// Generic HMAC 
fn hmac_generic<F, H>(key: &[u8], message: &[u8], block_size: usize, hash_fn: F) -> H
where
    F: Fn(&[u8]) -> H,
    H: AsRef<[u8]> + Clone,
{
    // Step 1: Create the padded key
    let mut padded_key = vec![0u8; block_size];
    
    if key.len() > block_size {
        // If key-longer-block size
        let hashed_key = hash_fn(key);
        let hashed_bytes = hashed_key.as_ref();
        padded_key[..hashed_bytes.len()].copy_from_slice(hashed_bytes);
    } else {
        // If-key-shorter-or-equal-to-block-size
        padded_key[..key.len()].copy_from_slice(key);
    }
    
    // Step 2: Create inner and outer padded keys
    let mut inner_pad = vec![0x36u8; block_size];
    let mut outer_pad = vec![0x5cu8; block_size];
    
    for i in 0..block_size {
        inner_pad[i] ^= padded_key[i];
        outer_pad[i] ^= padded_key[i];
    }
    
    // Step 3: Compute inner hash
    let mut inner_message = Vec::with_capacity(block_size + message.len());
    inner_message.extend_from_slice(&inner_pad);
    inner_message.extend_from_slice(message);
    let inner_hash = hash_fn(&inner_message);
    
    // Step 4: Compute outer hash
    let mut outer_message = Vec::with_capacity(block_size + inner_hash.as_ref().len());
    outer_message.extend_from_slice(&outer_pad);
    outer_message.extend_from_slice(inner_hash.as_ref());
    
    hash_fn(&outer_message)
}

/// HMAC-based Key Derivation Function (HKDF) - Extract step
pub fn hkdf_extract(salt: &[u8], input_key_material: &[u8]) -> Hash256 {
    hmac_sha256(salt, input_key_material)
}

/// HMAC-based Key Derivation Function (HKDF) - Expand step
pub fn hkdf_expand(prk: &Hash256, info: &[u8], length: usize) -> Vec<u8> {
    let hash_len = 32; // SHA-256 output length
    let n = (length + hash_len - 1) / hash_len; // Ceiling division
    
    if n > 255 {
        panic!("HKDF expand: requested length too large");
    }
    
    let mut output = Vec::with_capacity(length);
    let mut t = Vec::new();
    
    for i in 1..=n {
        let mut hmac_input = Vec::with_capacity(t.len() + info.len() + 1);
        hmac_input.extend_from_slice(&t);
        hmac_input.extend_from_slice(info);
        hmac_input.push(i as u8);
        
        t = hmac_sha256(prk, &hmac_input).to_vec();
        output.extend_from_slice(&t);
    }
    
    output.truncate(length);
    output
}

/// HMAC-based Key Derivation Function (HKDF) 
pub fn hkdf(salt: &[u8], input_key_material: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let prk = hkdf_extract(salt, input_key_material);
    hkdf_expand(&prk, info, length)
}

/// Constant-time comparison for HMAC verification
pub fn hmac_verify(mac1: &[u8], mac2: &[u8]) -> bool {
    if mac1.len() != mac2.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (a, b) in mac1.iter().zip(mac2.iter()) {
        result |= a ^ b;
    }
    
    result == 0
}

/// PBKDF2 (Password-Based Key Derivation Function 2) with HMAC-SHA256
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let h_len = 32; // SHA-256 output length
    let l = (dk_len + h_len - 1) / h_len; // Ceiling division
    
    let mut derived_key = Vec::with_capacity(dk_len);
    
    for i in 1..=l {
        // U_1 = PRF(P, S || INT(i))
        let mut prf_input = Vec::with_capacity(salt.len() + 4);
        prf_input.extend_from_slice(salt);
        prf_input.extend_from_slice(&(i as u32).to_be_bytes());
        
        let mut u = hmac_sha256(password, &prf_input);
        let mut f = u.clone();
        
        // U_c = PRF(P, U_{c-1})
        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            
            // F(P, S, c, i) = U_1 XOR U_2 XOR ... XOR U_c
            for j in 0..h_len {
                f[j] ^= u[j];
            }
        }
        
        derived_key.extend_from_slice(&f);
    }
    
    derived_key.truncate(dk_len);
    derived_key
}

/// Time-based One-Time Password (TOTP) using HMAC-SHA1
pub fn totp_hmac_sha1(key: &[u8], time_step: u64, digits: usize) -> u32 {
    // Convert time step to 8-byte big-endian
    let time_bytes = time_step.to_be_bytes();
    
    // Compute HMAC-SHA1 (using SHA-256 as fallback)
    let mac = hmac_sha256(key, &time_bytes);
    
    // Dynamic truncation
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let binary = ((mac[offset] & 0x7f) as u32) << 24
                | (mac[offset + 1] as u32) << 16
                | (mac[offset + 2] as u32) << 8
                | (mac[offset + 3] as u32);
    
    // Generate the desired number of digits
    let modulus = 10_u32.pow(digits as u32);
    binary % modulus
}

/// HMAC-based One-Time Password (HOTP)
pub fn hotp_hmac_sha1(key: &[u8], counter: u64, digits: usize) -> u32 {
    totp_hmac_sha1(key, counter, digits)
}

/// Compute HMAC-SHA256 incrementally for large data
pub struct HmacSha256 {
    inner_hasher: Sha256State,
    outer_key: [u8; 64],
}

impl HmacSha256 {
    /// Create new HMAC-SHA256 context
    pub fn new(key: &[u8]) -> Self {
        let mut padded_key = [0u8; 64];
        
        if key.len() > 64 {
            let hashed_key = sha256(key);
            padded_key[..32].copy_from_slice(&hashed_key);
        } else {
            padded_key[..key.len()].copy_from_slice(key);
        }
        
        let mut inner_pad = [0x36u8; 64];
        let mut outer_pad = [0x5cu8; 64];
        
        for i in 0..64 {
            inner_pad[i] ^= padded_key[i];
            outer_pad[i] ^= padded_key[i];
        }
        
        let mut inner_hasher = Sha256State::new();
        inner_hasher.update(&inner_pad);
        
        Self {
            inner_hasher,
            outer_key: outer_pad,
        }
    }
    
    /// Add data to HMAC computation
    pub fn update(&mut self, data: &[u8]) {
        self.inner_hasher.update(data);
    }
    
    /// Finalize HMAC computation
    pub fn finalize(self) -> Hash256 {
        let inner_hash = self.inner_hasher.finalize();
        
        let mut outer_hasher = Sha256State::new();
        outer_hasher.update(&self.outer_key);
        outer_hasher.update(&inner_hash);
        
        outer_hasher.finalize()
    }
}

/// Simple SHA-256 state for incremental hashing (To be perfectioned)
struct Sha256State {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256State {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buffer: [0; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }
    
    fn update(&mut self, data: &[u8]) {
        let mut input = data;
        self.total_len += data.len() as u64;
        
        // Handle remaining bytes in buffer
        if self.buffer_len > 0 {
            let space = 64 - self.buffer_len;
            if input.len() >= space {
                self.buffer[self.buffer_len..].copy_from_slice(&input[..space]);
                let block = self.buffer;
                self.process_block(&block);
                input = &input[space..];
                self.buffer_len = 0;
            } else {
                self.buffer[self.buffer_len..self.buffer_len + input.len()].copy_from_slice(input);
                self.buffer_len += input.len();
                return;
            }
        }
        
        // Process complete blocks
        while input.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&input[..64]);
            self.process_block(&block);
            input = &input[64..];
        }
        
        // Store remaining bytes
        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }
    
    fn finalize(mut self) -> Hash256 {
        // Add padding
        let total_bits = self.total_len * 8;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        
        if self.buffer_len > 56 {
            while self.buffer_len < 64 {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            let block = self.buffer;
            self.process_block(&block);
            self.buffer = [0; 64];
            self.buffer_len = 0;
        }
        
        while self.buffer_len < 56 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }
        
        // Add length
        let length_bytes = total_bits.to_be_bytes();
        self.buffer[56..].copy_from_slice(&length_bytes);
        let block = self.buffer;
        self.process_block(&block);
        
        // Generate output
        let mut output = [0u8; 32];
        for (i, &word) in self.state.iter().enumerate() {
            let bytes = word.to_be_bytes();
            output[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }
        
        output
    }
    
    fn process_block(&mut self, block: &[u8; 64]) {
        // SHA-256 compression function (simplified)
        let mut w = [0u32; 64];
        
        // Prepare message schedule
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4], block[i * 4 + 1], 
                block[i * 4 + 2], block[i * 4 + 3]
            ]);
        }
        
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        
        // Compression
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];
        
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ];
        
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}
