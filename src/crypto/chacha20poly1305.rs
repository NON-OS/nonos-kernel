//! ChaCha20-Poly1305 AEAD (RFC 8439) 

extern crate alloc;
use alloc::vec::Vec;
use crate::crypto::constant_time::ct_eq;
use core::ptr;

#[inline(always)]
fn zeroize(buf: &mut [u8]) {
    for b in buf {
        unsafe { ptr::write_volatile(b, 0) };
    }
}

// ChaCha20 block (RFC 8439)
fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32, out: &mut [u8; 64]) {
    fn u32le(x: &[u8]) -> u32 { u32::from_le_bytes([x[0], x[1], x[2], x[3]]) }
    let mut st = [0u32; 16];
    st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
    for i in 0..8 { st[4 + i] = u32le(&key[i*4..][..4]); }
    st[12] = counter;
    st[13] = u32le(&nonce[0..4]); st[14] = u32le(&nonce[4..8]); st[15] = u32le(&nonce[8..12]);
    let mut x = st;
    macro_rules! qr {
        ($a:expr,$b:expr,$c:expr,$d:expr) => {{
            x[$a] = x[$a].wrapping_add(x[$b]); x[$d] ^= x[$a]; x[$d] = x[$d].rotate_left(16);
            x[$c] = x[$c].wrapping_add(x[$d]); x[$b] ^= x[$c]; x[$b] = x[$b].rotate_left(12);
            x[$a] = x[$a].wrapping_add(x[$b]); x[$d] ^= x[$a]; x[$d] = x[$d].rotate_left(8);
            x[$c] = x[$c].wrapping_add(x[$d]); x[$b] ^= x[$c]; x[$b] = x[$b].rotate_left(7);
        }};
    }
    for _ in 0..10 {
        qr!(0,4,8,12); qr!(1,5,9,13); qr!(2,6,10,14); qr!(3,7,11,15);
        qr!(0,5,10,15); qr!(1,6,11,12); qr!(2,7,8,13); qr!(3,4,9,14);
    }
    for i in 0..16 {
        let w = x[i].wrapping_add(st[i]).to_le_bytes();
        out[i*4..i*4+4].copy_from_slice(&w);
    }
}

// Poly1305 (RFC 8439), returns 16-byte tag
fn poly1305_mac(msg: &[u8], key: &[u8; 32]) -> [u8; 16] {
    // clamp r
    let mut r = [0u8; 16]; r.copy_from_slice(&key[0..16]);
    r[3]  &= 15; r[7]  &= 15; r[11] &= 15; r[15] &= 15;
    r[4]  &= 252; r[8]  &= 252; r[12] &= 252;
    // r as 26-bit limbs
    let r0 = (u32::from_le_bytes([r[0],r[1],r[2],0])       ) & 0x3ffffff;
    let r1 = (u32::from_le_bytes([r[3],r[4],r[5],0]) >> 2) & 0x3ffffff;
    let r2 = (u32::from_le_bytes([r[6],r[7],r[8],0]) >> 4) & 0x3ffffff;
    let r3 = (u32::from_le_bytes([r[9],r[10],r[11],0])>> 6) & 0x3ffffff;
    let r4 = (u32::from_le_bytes([r[12],r[13],r[14],0])    ) & 0x3ffffff;

    let s1 = r1 * 5; let s2 = r2 * 5; let s3 = r3 * 5; let s4 = r4 * 5;

    let mut h0=0u32; let mut h1=0u32; let mut h2=0u32; let mut h3=0u32; let mut h4=0u32;

    let mut offset = 0usize;
    while offset < msg.len() {
        let n = core::cmp::min(16, msg.len() - offset);
        let mut block = [0u8; 17];
        block[..n].copy_from_slice(&msg[offset..offset + n]);
        block[n] = 1; // append 1 bit (byte)
        offset += n;

        let t0 = (u32::from_le_bytes([block[0],block[1],block[2],block[3]])      ) & 0x3ffffff;
        let t1 = (u32::from_le_bytes([block[3],block[4],block[5],block[6]]) >> 2) & 0x3ffffff;
        let t2 = (u32::from_le_bytes([block[6],block[7],block[8],block[9]]) >> 4) & 0x3ffffff;
        let t3 = (u32::from_le_bytes([block[9],block[10],block[11],block[12]])>> 6) & 0x3ffffff;
        let t4 = (u32::from_le_bytes([block[12],block[13],block[14],block[15]])    ) & 0x3ffffff;

        h0 = h0.wrapping_add(t0);
        h1 = h1.wrapping_add(t1);
        h2 = h2.wrapping_add(t2);
        h3 = h3.wrapping_add(t3);
        h4 = h4.wrapping_add(t4);

        let d0 = (h0 as u64) * (r0 as u64) + (h1 as u64) * (s4 as u64) + (h2 as u64) * (s3 as u64) + (h3 as u64) * (s2 as u64) + (h4 as u64) * (s1 as u64);
        let d1 = (h0 as u64) * (r1 as u64) + (h1 as u64) * (r0 as u64) + (h2 as u64) * (s4 as u64) + (h3 as u64) * (s3 as u64) + (h4 as u64) * (s2 as u64);
        let d2 = (h0 as u64) * (r2 as u64) + (h1 as u64) * (r1 as u64) + (h2 as u64) * (r0 as u64) + (h3 as u64) * (s4 as u64) + (h4 as u64) * (s3 as u64);
        let d3 = (h0 as u64) * (r3 as u64) + (h1 as u64) * (r2 as u64) + (h2 as u64) * (r1 as u64) + (h3 as u64) * (r0 as u64) + (h4 as u64) * (s4 as u64);
        let d4 = (h0 as u64) * (r4 as u64) + (h1 as u64) * (r3 as u64) + (h2 as u64) * (r2 as u64) + (h3 as u64) * (r1 as u64) + (h4 as u64) * (r0 as u64);

        let mut c;

        c = (d0 >> 26) as u32; h0 = (d0 as u32) & 0x3ffffff;
        let mut d1 = d1 + c as u64; c = (d1 >> 26) as u32; h1 = (d1 as u32) & 0x3ffffff;
        let mut d2 = d2 + c as u64; c = (d2 >> 26) as u32; h2 = (d2 as u32) & 0x3ffffff;
        let mut d3 = d3 + c as u64; c = (d3 >> 26) as u32; h3 = (d3 as u32) & 0x3ffffff;
        let mut d4 = d4 + c as u64; c = (d4 >> 26) as u32; h4 = (d4 as u32) & 0x3ffffff;
        h0 = h0.wrapping_add(c * 5);
        c = h0 >> 26; h0 &= 0x3ffffff;
        h1 = h1.wrapping_add(c);
    }

    // final reduction
    let mut c = h1 >> 26; h1 &= 0x3ffffff; h2 = h2.wrapping_add(c);
    c = h2 >> 26; h2 &= 0x3ffffff; h3 = h3.wrapping_add(c);
    c = h3 >> 26; h3 &= 0x3ffffff; h4 = h4.wrapping_add(c);
    c = h4 >> 26; h4 &= 0x3ffffff; h0 = h0.wrapping_add(c * 5);
    c = h0 >> 26; h0 &= 0x3ffffff; h1 = h1.wrapping_add(c);

    // compute g = h + -p
    let g0 = h0.wrapping_add(5); let c = g0 >> 26; let g0 = g0 & 0x3ffffff;
    let g1 = h1.wrapping_add(c); let c = g1 >> 26; let g1 = g1 & 0x3ffffff;
    let g2 = h2.wrapping_add(c); let c = g2 >> 26; let g2 = g2 & 0x3ffffff;
    let g3 = h3.wrapping_add(c); let c = g3 >> 26; let g3 = g3 & 0x3ffffff;
    let g4 = h4.wrapping_add(c).wrapping_add(1<<26);

    // select h if h < p else g
    let mask = (((g4 >> 26) & 1) as u32).wrapping_sub(1); // 0xFFFF_FFFF if h < p else 0
    let h0 = (h0 & mask) | (g0 & !mask);
    let h1 = (h1 & mask) | (g1 & !mask);
    let h2 = (h2 & mask) | (g2 & !mask);
    let h3 = (h3 & mask) | (g3 & !mask);
    let h4 = (h4 & mask) | (g4 & !mask);

    // serialize h
    let mut f = [0u8; 16];
    let mut t = (h0 | (h1 << 26)) as u64;
    f[0..4].copy_from_slice(&(t as u32).to_le_bytes());
    t = ((h1 >> 6) | (h2 << 20)) as u64;
    f[4..8].copy_from_slice(&(t as u32).to_le_bytes());
    t = ((h2 >> 12) | (h3 << 14)) as u64;
    f[8..12].copy_from_slice(&(t as u32).to_le_bytes());
    t = ((h3 >> 18) | (h4 << 8)) as u64;
    f[12..16].copy_from_slice(&(t as u32).to_le_bytes());

    // add s (second half of key)
    let mut tag = [0u8; 16];
    let s = &key[16..32];
    let mut carry = 0u16;
    for i in 0..16 {
        let v = f[i] as u16 + s[i] as u16 + carry;
        tag[i] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    tag
}

// AEAD

pub fn aead_encrypt(key: &[u8; 32], nonce12: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    // Poly1305 one-time key = ChaCha20(key, nonce, counter=0) first 32 bytes
    let mut block0 = [0u8; 64];
    chacha20_block(key, nonce12, 0, &mut block0);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);

    // Encrypt with counter starting at 1
    let mut out = plaintext.to_vec();
    let mut counter = 1u32;
    let mut off = 0usize;
    let mut keystream = [0u8; 64];
    while off < out.len() {
        chacha20_block(key, nonce12, counter, &mut keystream);
        let n = core::cmp::min(64, out.len() - off);
        for i in 0..n { out[off + i] ^= keystream[i]; }
        off += n;
        counter = counter.wrapping_add(1);
    }

    // Compute tag over AAD || pad || CT || pad || lens
    let pad = |len: usize| (16 - (len % 16)) % 16;
    let mut mac_input = Vec::with_capacity(aad.len() + pad(aad.len()) + out.len() + pad(out.len()) + 16);
    mac_input.extend_from_slice(aad);
    mac_input.extend_from_slice(&[0u8; 16][..pad(aad.len())]);
    mac_input.extend_from_slice(&out);
    mac_input.extend_from_slice(&[0u8; 16][..pad(out.len())]);
    mac_input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_input.extend_from_slice(&(out.len() as u64).to_le_bytes());

    let tag = poly1305_mac(&mac_input, &otk);

    // Zeroize sensitive temporaries
    zeroize(&mut otk);
    zeroize(&mut block0);
    zeroize(&mut keystream);
    zeroize(&mut mac_input);

    // out || tag
    let mut res = out;
    res.extend_from_slice(&tag);
    Ok(res)
}

pub fn aead_decrypt(key: &[u8; 32], nonce12: &[u8; 12], aad: &[u8], ciphertext_and_tag: &[u8]) -> Result<Vec<u8>, &'static str> {
    if ciphertext_and_tag.len() < 16 { return Err("ciphertext too short"); }
    let ct_len = ciphertext_and_tag.len() - 16;
    let (ct, tag) = ciphertext_and_tag.split_at(ct_len);

    let mut block0 = [0u8; 64];
    chacha20_block(key, nonce12, 0, &mut block0);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);

    // recompute tag
    let pad = |len: usize| (16 - (len % 16)) % 16;
    let mut mac_input = Vec::with_capacity(aad.len() + pad(aad.len()) + ct.len() + pad(ct.len()) + 16);
    mac_input.extend_from_slice(aad);
    mac_input.extend_from_slice(&[0u8; 16][..pad(aad.len())]);
    mac_input.extend_from_slice(ct);
    mac_input.extend_from_slice(&[0u8; 16][..pad(ct.len())]);
    mac_input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_input.extend_from_slice(&(ct.len() as u64).to_le_bytes());

    let expected = poly1305_mac(&mac_input, &otk);
    let ok = ct_eq(&expected, tag);

    // zeroize before branching return
    zeroize(&mut otk);
    zeroize(&mut block0);
    zeroize(&mut mac_input);

    if !ok { return Err("tag mismatch"); }

    // decrypt
    let mut out = ct.to_vec();
    let mut counter = 1u32;
    let mut off = 0usize;
    let mut keystream = [0u8; 64];
    while off < out.len() {
        chacha20_block(key, nonce12, counter, &mut keystream);
        let n = core::cmp::min(64, out.len() - off);
        for i in 0..n { out[off + i] ^= keystream[i]; }
        off += n;
        counter = counter.wrapping_add(1);
    }
    zeroize(&mut keystream);
    Ok(out)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    // RFC 8439 test vector (Section 2.8.2 AEAD_CHACHA20_POLY1305)
    #[test]
    fn rfc8439_vector() {
        let key = [
            0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
            0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
        ];
        let nonce = [0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47];
        let aad = [0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7];
        let pt = [
            0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,0x6e,0x64,0x20,0x47,0x65,0x6e,0x74,0x6c,
            0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,
            0x73,0x20,0x6f,0x66,0x20,0x27,0x39,0x39,0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,
            0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,0x65,0x72,0x20,0x79,0x6f,0x75,0x20,0x6f,
            0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,
            0x74,0x68,0x65,0x20,0x66,0x75,0x74,0x75,0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,
            0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,0x75,0x6c,0x64,0x20,0x62,0x65,0x20,0x69,
            0x74,0x2e
        ];
        let ct_and_tag = aead_encrypt(&key, &nonce, &aad, &pt).unwrap();
        // Decrypt must succeed and recover plaintext
        let dec = aead_decrypt(&key, &nonce, &aad, &ct_and_tag).unwrap();
        assert_eq!(dec, pt);
        // Tamper tag
        let mut bad = ct_and_tag.clone();
        let last = bad.len()-1; bad[last] ^= 1;
        assert!(aead_decrypt(&key, &nonce, &aad, &bad).is_err());
    }
}
