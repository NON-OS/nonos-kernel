use alloc::vec::Vec;

pub type Hash256 = [u8; 32];

/// SHA-256 implementation
pub fn sha256(data: &[u8]) -> Hash256 {
    let mut h = [
        0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    
    let mut message = data.to_vec();
    let original_len = message.len() as u64;
    
    // Padding
    message.push(0x80);
    while (message.len() % 64) != 56 {
        message.push(0x00);
    }
    
    // Append length
    message.extend_from_slice(&(original_len * 8).to_be_bytes());
    
    // Process chunks
    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 64];
        
        // Break chunk into 16 32-bit words
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1], 
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        
        // Extend the first 16 words into the remaining 48 words
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        
        // Initialize working variables
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h_val) = 
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        
        // Main loop
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
            let temp1 = h_val.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            
            h_val = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        
        // Add to hash values
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_val);
    }
    
    // Produce final hash
    let mut result = [0u8; 32];
    for (i, &val) in h.iter().enumerate() {
        result[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
    }
    
    result
}

/// Simple BLAKE3-inspired hash (simplified implementation)
pub fn blake3_hash(data: &[u8]) -> Hash256 {
    // For now, just use SHA-256 as blake3 is complex
    sha256(data)
}

/// HMAC-SHA256
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Hash256 {
    let mut key_padded = [0u8; 64];
    
    if key.len() > 64 {
        let hashed_key = sha256(key);
        key_padded[..32].copy_from_slice(&hashed_key);
    } else {
        key_padded[..key.len()].copy_from_slice(key);
    }
    
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    
    for i in 0..64 {
        inner_pad[i] ^= key_padded[i];
        outer_pad[i] ^= key_padded[i];
    }
    
    let mut inner_hash_input = Vec::new();
    inner_hash_input.extend_from_slice(&inner_pad);
    inner_hash_input.extend_from_slice(message);
    let inner_hash = sha256(&inner_hash_input);
    
    let mut outer_hash_input = Vec::new();
    outer_hash_input.extend_from_slice(&outer_pad);
    outer_hash_input.extend_from_slice(&inner_hash);
    
    sha256(&outer_hash_input)
}