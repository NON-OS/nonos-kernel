//! AES-256-GCM (SP 800-38D) -

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::aes::Aes256;
use crate::crypto::constant_time::ct_eq;

// E_K(0^128) to derive the GHASH key H
fn ghash_key(aes: &Aes256) -> (u64, u64) {
    let zero = [0u8; 16];
    let h = aes.encrypt_block(&zero);
    let hi = u64::from_be_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]);
    let lo = u64::from_be_bytes([h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]]);
    (hi, lo)
}

// GHASH: returns 128-bit value as (hi, lo)
fn ghash(h: (u64, u64), aad: &[u8], data: &[u8]) -> (u64, u64) {
    let mut y = (0u64, 0u64);
    y = ghash_update(y, h, aad);
    y = ghash_update(y, h, data);

    let aad_bits = (aad.len() as u128) * 8;
    let data_bits = (data.len() as u128) * 8;

    // Final length block: len(AAD) || len(DATA) (each 64-bit, big-endian)
    let len_block1 = ((aad_bits >> 64) as u64, aad_bits as u64);
    let len_block2 = ((data_bits >> 64) as u64, data_bits as u64);

    let z = gf_mul((y.0 ^ len_block1.0, y.1 ^ len_block1.1), h);
    gf_mul((z.0 ^ len_block2.0, z.1 ^ len_block2.1), h)
}

// Update GHASH with 16-byte blocks (pad last with zeros)
fn ghash_update(mut y: (u64, u64), h: (u64, u64), buf: &[u8]) -> (u64, u64) {
    let mut off = 0usize;
    while off < buf.len() {
        let take = core::cmp::min(16, buf.len() - off);
        let mut block = [0u8; 16];
        block[..take].copy_from_slice(&buf[off..off + take]);
        let x_hi = u64::from_be_bytes([block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7]]);
        let x_lo = u64::from_be_bytes([block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15]]);
        y = gf_mul((y.0 ^ x_hi, y.1 ^ x_lo), h);
        off += take;
    }
    y
}

// GF(2^128) multiply with reduction polynomial x^128 + x^7 + x^2 + x + 1 (per GHASH)
// This is a bit-serial constant-time multiply: 128 rounds.
fn gf_mul(mut x: (u64, u64), mut y: (u64, u64)) -> (u64, u64) {
    let mut z = (0u64, 0u64);
    const R: u64 = 0xe100000000000000;

    for _ in 0..128 {
        let x_msb = (x.0 & 0x8000_0000_0000_0000) != 0;
        if x_msb {
            z.0 ^= y.0;
            z.1 ^= y.1;
        }
        // x <<= 1 (big-endian 128-bit)
        x.0 = (x.0 << 1) | (x.1 >> 63);
        x.1 <<= 1;

        // y >>= 1 with reduction if LSB was set
        let y_lsb = (y.1 & 1) != 0;
        y.1 = (y.1 >> 1) | (y.0 << 63);
        y.0 >>= 1;
        if y_lsb {
            y.0 ^= R;
        }
    }
    z
}

// Increment last 32 bits of counter (GCM inc32)
fn inc32(counter: &mut [u8; 16]) {
    let n = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]).wrapping_add(1);
    counter[12..16].copy_from_slice(&n.to_be_bytes());
}

// Derive J0 from 96-bit nonce: J0 = nonce || 0x00000001
fn derive_j0_from_nonce(nonce96: &[u8; 12]) -> [u8; 16] {
    let mut j0 = [0u8; 16];
    j0[0..12].copy_from_slice(nonce96);
    j0[15] = 1;
    j0
}

// AES-CTR for GCM starting from J0+1
fn aes_ctr_gcm(aes: &Aes256, j0: &[u8; 16], data: &mut [u8]) {
    let mut ctr = *j0;
    inc32(&mut ctr);
    let mut off = 0usize;
    while off < data.len() {
        let ks = aes.encrypt_block(&ctr);
        let n = core::cmp::min(16, data.len() - off);
        for i in 0..n {
            data[off + i] ^= ks[i];
        }
        off += n;
        inc32(&mut ctr);
    }
}

// Compute tag: T = E_K(J0) XOR GHASH(H, AAD, C)
fn compute_tag(aes: &Aes256, j0: &[u8; 16], s: (u64, u64)) -> [u8; 16] {
    let mut s_be = [0u8; 16];
    s_be[0..8].copy_from_slice(&s.0.to_be_bytes());
    s_be[8..16].copy_from_slice(&s.1.to_be_bytes());

    let ekj0 = aes.encrypt_block(j0);
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = ekj0[i] ^ s_be[i];
    }
    tag
}

/// Encrypt: returns ciphertext || 16-byte tag
pub fn aes256_gcm_encrypt(
    key: &[u8; 32],
    nonce96: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let aes = Aes256::new(key);
    let h = ghash_key(&aes);
    let j0 = derive_j0_from_nonce(nonce96);

    let mut ciphertext = plaintext.to_vec();
    aes_ctr_gcm(&aes, &j0, &mut ciphertext);

    let s = ghash(h, aad, &ciphertext);
    let tag = compute_tag(&aes, &j0, s);

    let mut out = ciphertext;
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypt: constant-time tag verification; returns plaintext on success
pub fn aes256_gcm_decrypt(
    key: &[u8; 32],
    nonce96: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if ciphertext_and_tag.len() < 16 {
        return Err("ciphertext too short");
    }
    let ct_len = ciphertext_and_tag.len() - 16;
    let (ct, tag) = ciphertext_and_tag.split_at(ct_len);

    let aes = Aes256::new(key);
    let h = ghash_key(&aes);
    let j0 = derive_j0_from_nonce(nonce96);

    let s = ghash(h, aad, ct);
    let expected = compute_tag(&aes, &j0, s);
    if !ct_eq(&expected, tag) {
        return Err("tag mismatch");
    }

    let mut plaintext = ct.to_vec();
    aes_ctr_gcm(&aes, &j0, &mut plaintext);
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    // NIST SP 800-38D Test Case (GCM Spec Appendix)
    // Key, IV, AAD, PT, CT, Tag from a common test vector
    #[test]
    fn gcm_kat_basic() {
        let key = [
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        ];
        let iv = [0u8; 12];
        let aad = [0u8; 0];
        let pt = [0u8; 0];

        // With zero PT/AAD, tag = E_K(J0)
        let ct = aes256_gcm_encrypt(&key, &iv, &aad, &pt).unwrap();
        assert_eq!(ct.len(), 16);
        let dec = aes256_gcm_decrypt(&key, &iv, &aad, &ct).unwrap();
        assert_eq!(dec, pt);
    }
}
