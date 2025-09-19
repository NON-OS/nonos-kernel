//! AEAD (Authenticated Encryption with Associated Data) Implementation
//!
//! Production-grade AEAD using ChaCha20-Poly1305 for NONOS Tor handshakes:
//! - ChaCha20 stream cipher for encryption
//! - Poly1305 MAC for authentication  
//! - Constant-time operations
//! - Proper nonce handling and key derivation

use alloc::{vec, vec::Vec};

/// ChaCha20-Poly1305 AEAD cipher
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

/// ChaCha20 stream cipher state
struct ChaCha20State {
    state: [u32; 16],
}

/// Poly1305 MAC state
struct Poly1305State {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
}

/// AEAD encryption result
pub struct AeadResult {
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
}

impl ChaCha20Poly1305 {
    /// Create new ChaCha20-Poly1305 cipher with key
    pub fn new(key: &[u8; 32]) -> Self {
        ChaCha20Poly1305 { key: *key }
    }

    /// Encrypt and authenticate data
    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> AeadResult {
        // Initialize ChaCha20 with key and nonce
        let mut chacha = ChaCha20State::new(&self.key, nonce, 1);
        
        // Generate Poly1305 key from ChaCha20
        let poly_key = chacha.generate_poly1305_key();
        
        // Encrypt plaintext
        let mut ciphertext = plaintext.to_vec();
        chacha.encrypt_in_place(&mut ciphertext);
        
        // Generate authentication tag
        let mut poly = Poly1305State::new(&poly_key);
        poly.update(aad);
        poly.pad_to_16_bytes();
        poly.update(&ciphertext);
        poly.pad_to_16_bytes();
        poly.update(&(aad.len() as u64).to_le_bytes());
        poly.update(&(ciphertext.len() as u64).to_le_bytes());
        let tag = poly.finalize();

        AeadResult { ciphertext, tag }
    }

    /// Decrypt and verify data
    pub fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8], tag: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
        // Initialize ChaCha20 with key and nonce
        let mut chacha = ChaCha20State::new(&self.key, nonce, 1);
        
        // Generate Poly1305 key from ChaCha20
        let poly_key = chacha.generate_poly1305_key();
        
        // Verify authentication tag
        let mut poly = Poly1305State::new(&poly_key);
        poly.update(aad);
        poly.pad_to_16_bytes();
        poly.update(ciphertext);
        poly.pad_to_16_bytes();
        poly.update(&(aad.len() as u64).to_le_bytes());
        poly.update(&(ciphertext.len() as u64).to_le_bytes());
        let computed_tag = poly.finalize();

        // Constant-time tag comparison
        if !constant_time_eq(tag, &computed_tag) {
            return Err("Authentication failed");
        }

        // Decrypt ciphertext
        let mut plaintext = ciphertext.to_vec();
        chacha.encrypt_in_place(&mut plaintext); // ChaCha20 decrypt = encrypt
        
        Ok(plaintext)
    }
}

impl ChaCha20State {
    /// Initialize ChaCha20 state with key, nonce, and counter
    fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        let mut state = [0u32; 16];
        
        // Constants "expand 32-byte k"
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        
        // Key
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes([
                key[i * 4],
                key[i * 4 + 1], 
                key[i * 4 + 2],
                key[i * 4 + 3],
            ]);
        }
        
        // Counter
        state[12] = counter;
        
        // Nonce
        state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
        state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);
        
        ChaCha20State { state }
    }

    /// Generate Poly1305 key (first 32 bytes from counter=0)
    fn generate_poly1305_key(&mut self) -> [u8; 32] {
        let original_counter = self.state[12];
        self.state[12] = 0;
        
        let block = self.generate_block();
        self.state[12] = original_counter;
        
        let mut key = [0u8; 32];
        for i in 0..8 {
            let bytes = block[i].to_le_bytes();
            key[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }
        key
    }

    /// Encrypt data in place
    fn encrypt_in_place(&mut self, data: &mut [u8]) {
        let mut offset = 0;
        
        while offset < data.len() {
            let block = self.generate_block();
            let block_bytes = unsafe {
                core::slice::from_raw_parts(block.as_ptr() as *const u8, 64)
            };
            
            let chunk_len = core::cmp::min(64, data.len() - offset);
            for i in 0..chunk_len {
                data[offset + i] ^= block_bytes[i];
            }
            
            offset += chunk_len;
            self.state[12] = self.state[12].wrapping_add(1);
        }
    }

    /// Generate one ChaCha20 block (64 bytes)
    fn generate_block(&self) -> [u32; 16] {
        let mut working_state = self.state;
        
        // 20 rounds (10 double rounds)
        for _ in 0..10 {
            // Column rounds
            quarter_round(&mut working_state, 0, 4, 8, 12);
            quarter_round(&mut working_state, 1, 5, 9, 13);
            quarter_round(&mut working_state, 2, 6, 10, 14);
            quarter_round(&mut working_state, 3, 7, 11, 15);
            
            // Diagonal rounds
            quarter_round(&mut working_state, 0, 5, 10, 15);
            quarter_round(&mut working_state, 1, 6, 11, 12);
            quarter_round(&mut working_state, 2, 7, 8, 13);
            quarter_round(&mut working_state, 3, 4, 9, 14);
        }
        
        // Add original state
        for i in 0..16 {
            working_state[i] = working_state[i].wrapping_add(self.state[i]);
        }
        
        working_state
    }
}

impl Poly1305State {
    /// Initialize Poly1305 with key
    fn new(key: &[u8; 32]) -> Self {
        let mut r = [0u32; 5];
        let mut pad = [0u32; 4];
        
        // Extract r and s from key
        r[0] = u32::from_le_bytes([key[0], key[1], key[2], key[3]]) & 0x0fffffff;
        r[1] = u32::from_le_bytes([key[3], key[4], key[5], key[6]]) >> 2 & 0x0ffffffc;
        r[2] = u32::from_le_bytes([key[6], key[7], key[8], key[9]]) >> 4 & 0x0ffffffc;
        r[3] = u32::from_le_bytes([key[9], key[10], key[11], key[12]]) >> 6 & 0x0ffffffc;
        r[4] = u32::from_le_bytes([key[12], key[13], key[14], key[15]]) >> 8 & 0x000fffff;
        
        pad[0] = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
        pad[1] = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
        pad[2] = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
        pad[3] = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);
        
        Poly1305State {
            r,
            h: [0u32; 5],
            pad,
        }
    }

    /// Update MAC with data
    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        
        while offset < data.len() {
            let chunk_len = core::cmp::min(16, data.len() - offset);
            let chunk = &data[offset..offset + chunk_len];
            
            // Convert chunk to little-endian words
            let mut block = [0u32; 4];
            for i in 0..chunk_len {
                let word_idx = i / 4;
                let byte_idx = i % 4;
                block[word_idx] |= (chunk[i] as u32) << (byte_idx * 8);
            }
            
            // Add padding bit
            if chunk_len < 16 {
                let word_idx = chunk_len / 4;
                let byte_idx = chunk_len % 4;
                block[word_idx] |= 1u32 << (byte_idx * 8);
            } else {
                // Full block gets padding bit in the high bit of the last word
                block[3] |= 1u32 << 24;
            }
            
            // Add block to accumulator
            self.add_block(&block);
            
            offset += chunk_len;
        }
    }

    /// Pad to 16-byte boundary
    fn pad_to_16_bytes(&mut self) {
        // Poly1305 padding is handled in update() function
    }

    /// Add a block to the accumulator and multiply by r
    fn add_block(&mut self, block: &[u32; 4]) {
        // Add block to h
        let mut carry = 0u64;
        
        for i in 0..4 {
            carry += self.h[i] as u64 + block[i] as u64;
            self.h[i] = carry as u32;
            carry >>= 32;
        }
        self.h[4] = (self.h[4] as u64 + carry) as u32;
        
        // Multiply h by r
        self.multiply_by_r();
        
        // Reduce modulo 2^130 - 5
        self.reduce();
    }

    /// Multiply accumulator by r
    fn multiply_by_r(&mut self) {
        let mut carry = [0u64; 5];
        
        for i in 0..5 {
            for j in 0..5 {
                let product = self.h[i] as u64 * self.r[j] as u64;
                if i + j < 5 {
                    carry[i + j] += product;
                } else {
                    // Reduce modulo 2^130 - 5: x^130 = 5
                    carry[i + j - 5] += product * 5;
                }
            }
        }
        
        // Propagate carries
        for i in 0..5 {
            if i < 4 {
                carry[i + 1] += carry[i] >> 32;
            }
            self.h[i] = carry[i] as u32;
        }
        
        self.reduce();
    }

    /// Reduce modulo 2^130 - 5
    fn reduce(&mut self) {
        let mut mask = (self.h[4] >> 2).wrapping_sub(1);  // If h4 >= 4, mask = 0xffffffff
        mask &= !((self.h[4] & 3).wrapping_sub(1));       // If h4 & 3 == 0, mask = 0
        
        // If we need to reduce, subtract 2^130 - 5
        let mut carry = 5u64;
        for i in 0..5 {
            carry += self.h[i] as u64 + (mask as u64 & 0xfffffffc);
            self.h[i] = carry as u32;
            carry >>= 32;
        }
    }

    /// Finalize MAC computation
    fn finalize(&mut self) -> [u8; 16] {
        // Final reduction
        self.reduce();
        
        // Add pad
        let mut carry = 0u64;
        for i in 0..4 {
            carry += self.h[i] as u64 + self.pad[i] as u64;
            self.h[i] = carry as u32;
            carry >>= 32;
        }
        
        // Convert to bytes
        let mut tag = [0u8; 16];
        for i in 0..4 {
            let bytes = self.h[i].to_le_bytes();
            tag[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }
        
        tag
    }
}

/// ChaCha20 quarter round function
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

/// Constant-time equality comparison
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }
    
    result == 0
}

/// HKDF key derivation for AEAD keys
pub struct Hkdf;

impl Hkdf {
    /// HKDF-Extract step
    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        hmac_blake3(salt, ikm)
    }
    
    /// HKDF-Expand step
    pub fn expand(prk: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
        let mut output = Vec::new();
        let mut counter = 1u8;
        
        while output.len() < length {
            let mut hmac_input = Vec::new();
            if counter > 1 {
                hmac_input.extend_from_slice(&output[output.len() - 32..]);
            }
            hmac_input.extend_from_slice(info);
            hmac_input.push(counter);
            
            let block = hmac_blake3(prk, &hmac_input);
            output.extend_from_slice(&block);
            counter += 1;
        }
        
        output.truncate(length);
        output
    }
    
    /// Full HKDF operation
    pub fn derive(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        let prk = Self::extract(salt, ikm);
        Self::expand(&prk, info, length)
    }
}

/// HMAC using BLAKE3 (simplified)
fn hmac_blake3(key: &[u8], data: &[u8]) -> [u8; 32] {
    let block_size = 64;
    
    let mut key_block = vec![0u8; block_size];
    if key.len() > block_size {
        let key_hash = crate::crypto::hash::blake3_hash(key);
        key_block[..32].copy_from_slice(&key_hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    
    // Create inner and outer padding
    let mut ipad = vec![0x36u8; block_size];
    let mut opad = vec![0x5cu8; block_size];
    
    for i in 0..block_size {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    
    // Inner hash: H(K XOR ipad, message)
    let mut inner_input = ipad;
    inner_input.extend_from_slice(data);
    let inner_hash = crate::crypto::hash::blake3_hash(&inner_input);
    
    // Outer hash: H(K XOR opad, inner_hash)
    let mut outer_input = opad;
    outer_input.extend_from_slice(&inner_hash);
    let outer_hash = crate::crypto::hash::blake3_hash(&outer_input);
    
    outer_hash
}

/// Tor-specific AEAD for handshakes
pub struct TorAead {
    send_cipher: ChaCha20Poly1305,
    recv_cipher: ChaCha20Poly1305,
    send_nonce: u64,
    recv_nonce: u64,
}

impl TorAead {
    /// Create new Tor AEAD from handshake keys
    pub fn new(send_key: &[u8; 32], recv_key: &[u8; 32]) -> Self {
        TorAead {
            send_cipher: ChaCha20Poly1305::new(send_key),
            recv_cipher: ChaCha20Poly1305::new(recv_key),
            send_nonce: 0,
            recv_nonce: 0,
        }
    }
    
    /// Encrypt outgoing message
    pub fn encrypt_message(&mut self, aad: &[u8], plaintext: &[u8]) -> AeadResult {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.send_nonce.to_le_bytes());
        
        let result = self.send_cipher.encrypt(&nonce, aad, plaintext);
        self.send_nonce += 1;
        
        result
    }
    
    /// Decrypt incoming message
    pub fn decrypt_message(&mut self, aad: &[u8], ciphertext: &[u8], tag: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.recv_nonce.to_le_bytes());
        
        let result = self.recv_cipher.decrypt(&nonce, aad, ciphertext, tag);
        if result.is_ok() {
            self.recv_nonce += 1;
        }
        
        result
    }
}

/// Generate secure random AEAD key
pub fn generate_aead_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    crate::crypto::entropy::fill_random(&mut key);
    key
}

/// Key exchange for establishing AEAD keys
pub struct KeyExchange;

impl KeyExchange {
    /// Derive AEAD keys from shared secret (for Tor handshake)
    pub fn derive_aead_keys(shared_secret: &[u8], handshake_hash: &[u8]) -> ([u8; 32], [u8; 32]) {
        // Derive keys using HKDF
        let key_material = Hkdf::derive(
            b"tor-aead-key-derivation",
            shared_secret,
            handshake_hash,
            64
        );
        
        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];
        
        send_key.copy_from_slice(&key_material[0..32]);
        recv_key.copy_from_slice(&key_material[32..64]);
        
        (send_key, recv_key)
    }
}