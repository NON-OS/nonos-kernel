extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::symmetric::aes_gcm::{
    aes128_gcm_encrypt, aes128_gcm_decrypt, Aes128Gcm,
    aes256_gcm_encrypt, aes256_gcm_decrypt, Aes256Gcm,
};
use crate::crypto::symmetric::chacha20poly1305::{
    aead_encrypt, aead_decrypt, aead_encrypt_in_place, aead_decrypt_in_place,
    chacha20_block, poly1305_mac, TAG_SIZE,
};

#[test]
fn aes128_gcm_nist_test_case_1() {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let aad: &[u8] = &[];
    let pt: &[u8] = &[];

    let expected_tag: [u8; 16] = [
        0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
        0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a,
    ];

    let ct = aes128_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
    assert_eq!(ct.len(), 16);
    assert_eq!(&ct[..], &expected_tag[..]);

    let dec = aes128_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec.len(), 0);
}

#[test]
fn aes128_gcm_nist_test_case_2() {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let aad: &[u8] = &[];
    let pt = [0u8; 16];

    let expected_ct: [u8; 16] = [
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
    ];
    let expected_tag: [u8; 16] = [
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
    ];

    let result = aes128_gcm_encrypt(&key, &nonce, aad, &pt).unwrap();
    assert_eq!(result.len(), 32);

    let ct = &result[..16];
    let tag = &result[16..];
    assert_eq!(ct, &expected_ct[..]);
    assert_eq!(tag, &expected_tag[..]);

    let dec = aes128_gcm_decrypt(&key, &nonce, aad, &result).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn aes128_gcm_roundtrip() {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"additional authenticated data";
    let pt = b"secret message to encrypt";

    let ct = aes128_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
    assert_eq!(ct.len(), pt.len() + 16);

    let dec = aes128_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn aes128_gcm_tag_tampering_fails() {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"secret";

    let mut ct = aes128_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x01;

    assert!(aes128_gcm_decrypt(&key, &nonce, aad, &ct).is_err());
}

#[test]
fn aes128_gcm_ciphertext_tampering_fails() {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"secret";

    let mut ct = aes128_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
    ct[0] ^= 0x01;

    assert!(aes128_gcm_decrypt(&key, &nonce, aad, &ct).is_err());
}

#[test]
fn aes128_gcm_aad_tampering_fails() {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"secret";

    let ct = aes128_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
    let wrong_aad = b"Header";

    assert!(aes128_gcm_decrypt(&key, &nonce, wrong_aad, &ct).is_err());
}

#[test]
fn aes128_gcm_short_ciphertext_fails() {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let short_ct = [0u8; 15];

    assert!(aes128_gcm_decrypt(&key, &nonce, aad, &short_ct).is_err());
}

#[test]
fn aes128_gcm_empty_plaintext() {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"";

    let ct = aes128_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
    assert_eq!(ct.len(), 16);

    let dec = aes128_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn aes128_gcm_empty_aad() {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"";
    let pt = b"secret message";

    let ct = aes128_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
    let dec = aes128_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn aes128_gcm_in_place_encrypt_decrypt() {
    let gcm = Aes128Gcm::new(&[0x42u8; 16]);
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"secret message for in-place";

    let mut buffer = pt.to_vec();
    let tag = gcm.encrypt_in_place(&nonce, aad, &mut buffer);

    gcm.decrypt_in_place(&nonce, aad, &mut buffer, &tag).unwrap();
    assert_eq!(&buffer[..], pt);
}

#[test]
fn aes128_gcm_in_place_tag_tampering_fails() {
    let gcm = Aes128Gcm::new(&[0x42u8; 16]);
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"secret";

    let mut buffer = pt.to_vec();
    let mut tag = gcm.encrypt_in_place(&nonce, aad, &mut buffer);
    tag[0] ^= 0x01;

    assert!(gcm.decrypt_in_place(&nonce, aad, &mut buffer, &tag).is_err());
}

#[test]
fn aes128_gcm_large_plaintext() {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"header";

    let pt: Vec<u8> = (0..4096).map(|i| i as u8).collect();

    let ct = aes128_gcm_encrypt(&key, &nonce, aad, &pt).unwrap();
    let dec = aes128_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn aes256_gcm_roundtrip() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"additional authenticated data";
    let pt = b"secret message to encrypt with aes256";

    let ct = aes256_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
    assert_eq!(ct.len(), pt.len() + 16);

    let dec = aes256_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn aes256_gcm_tag_tampering_fails() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"secret";

    let mut ct = aes256_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x01;

    assert!(aes256_gcm_decrypt(&key, &nonce, aad, &ct).is_err());
}

#[test]
fn aes256_gcm_ciphertext_tampering_fails() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"secret";

    let mut ct = aes256_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
    ct[0] ^= 0x01;

    assert!(aes256_gcm_decrypt(&key, &nonce, aad, &ct).is_err());
}

#[test]
fn aes256_gcm_empty_plaintext() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"";

    let ct = aes256_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
    assert_eq!(ct.len(), 16);

    let dec = aes256_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn aes256_gcm_in_place_encrypt_decrypt() {
    let gcm = Aes256Gcm::new(&[0x42u8; 32]);
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"secret message for in-place aes256";

    let mut buffer = pt.to_vec();
    let tag = gcm.encrypt_in_place(&nonce, aad, &mut buffer);

    gcm.decrypt_in_place(&nonce, aad, &mut buffer, &tag).unwrap();
    assert_eq!(&buffer[..], pt);
}

#[test]
fn chacha20_rfc8439_block_test() {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00,
    ];

    let mut output = [0u8; 64];
    chacha20_block(&key, &nonce, 1, &mut output);

    let expected = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
        0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
        0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
        0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
        0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    ];
    assert_eq!(output, expected);
}

#[test]
fn chacha20_poly1305_rfc8439_aead() {
    let key = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let nonce = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47,
    ];
    let aad = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let plaintext = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";

    let expected_ciphertext = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    ];

    let expected_tag = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    ];

    let result = aead_encrypt(&key, &nonce, &aad, plaintext).unwrap();

    assert_eq!(&result[..expected_ciphertext.len()], &expected_ciphertext[..]);
    assert_eq!(&result[expected_ciphertext.len()..], &expected_tag[..]);

    let decrypted = aead_decrypt(&key, &nonce, &aad, &result).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn chacha20_poly1305_tag_tampering_fails() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let mut ciphertext = aead_encrypt(&key, &nonce, aad, plaintext).unwrap();
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;

    assert!(aead_decrypt(&key, &nonce, aad, &ciphertext).is_err());
}

#[test]
fn chacha20_poly1305_ciphertext_tampering_fails() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let mut ciphertext = aead_encrypt(&key, &nonce, aad, plaintext).unwrap();
    ciphertext[0] ^= 0x01;

    assert!(aead_decrypt(&key, &nonce, aad, &ciphertext).is_err());
}

#[test]
fn chacha20_poly1305_aad_tampering_fails() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let ciphertext = aead_encrypt(&key, &nonce, aad, plaintext).unwrap();
    let wrong_aad = b"Header";

    assert!(aead_decrypt(&key, &nonce, wrong_aad, &ciphertext).is_err());
}

#[test]
fn chacha20_poly1305_empty_plaintext() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"";

    let ciphertext = aead_encrypt(&key, &nonce, aad, plaintext).unwrap();
    assert_eq!(ciphertext.len(), TAG_SIZE);

    let decrypted = aead_decrypt(&key, &nonce, aad, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn chacha20_poly1305_empty_aad() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"";
    let plaintext = b"secret data";

    let ciphertext = aead_encrypt(&key, &nonce, aad, plaintext).unwrap();
    let decrypted = aead_decrypt(&key, &nonce, aad, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn chacha20_poly1305_in_place() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"secret data for in-place test";

    let mut buffer = [0u8; 256];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    let ct_len = aead_encrypt_in_place(&key, &nonce, aad, &mut buffer, plaintext.len()).unwrap();

    let pt_len = aead_decrypt_in_place(&key, &nonce, aad, &mut buffer, ct_len).unwrap();

    assert_eq!(pt_len, plaintext.len());
    assert_eq!(&buffer[..pt_len], plaintext);
}

#[test]
fn chacha20_poly1305_large_plaintext() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";

    let plaintext: Vec<u8> = (0..4096).map(|i| i as u8).collect();

    let ciphertext = aead_encrypt(&key, &nonce, aad, &plaintext).unwrap();
    let decrypted = aead_decrypt(&key, &nonce, aad, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn poly1305_rfc8439_mac() {
    let key = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
    ];
    let msg = b"Cryptographic Forum Research Group";

    let tag = poly1305_mac(msg, &key);

    let expected = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
    ];
    assert_eq!(tag, expected);
}

#[test]
fn poly1305_deterministic() {
    let key = [0xff; 32];
    let tag1 = poly1305_mac(b"test", &key);
    let tag2 = poly1305_mac(b"test", &key);
    assert_eq!(tag1, tag2);
}

#[test]
fn chacha20_poly1305_short_ciphertext_fails() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let short_ct = [0u8; 15];

    assert!(aead_decrypt(&key, &nonce, aad, &short_ct).is_err());
}

#[test]
fn chacha20_poly1305_different_keys_different_output() {
    let key1 = [0x42u8; 32];
    let key2 = [0x43u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let ct1 = aead_encrypt(&key1, &nonce, aad, plaintext).unwrap();
    let ct2 = aead_encrypt(&key2, &nonce, aad, plaintext).unwrap();

    assert_ne!(ct1, ct2);
}

#[test]
fn chacha20_poly1305_different_nonces_different_output() {
    let key = [0x42u8; 32];
    let nonce1 = [0x24u8; 12];
    let nonce2 = [0x25u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let ct1 = aead_encrypt(&key, &nonce1, aad, plaintext).unwrap();
    let ct2 = aead_encrypt(&key, &nonce2, aad, plaintext).unwrap();

    assert_ne!(ct1, ct2);
}

#[test]
fn aes_gcm_different_keys_different_output() {
    let key1 = [0x42u8; 16];
    let key2 = [0x43u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let ct1 = aes128_gcm_encrypt(&key1, &nonce, aad, plaintext).unwrap();
    let ct2 = aes128_gcm_encrypt(&key2, &nonce, aad, plaintext).unwrap();

    assert_ne!(ct1, ct2);
}

#[test]
fn aes_gcm_different_nonces_different_output() {
    let key = [0x42u8; 16];
    let nonce1 = [0x24u8; 12];
    let nonce2 = [0x25u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let ct1 = aes128_gcm_encrypt(&key, &nonce1, aad, plaintext).unwrap();
    let ct2 = aes128_gcm_encrypt(&key, &nonce2, aad, plaintext).unwrap();

    assert_ne!(ct1, ct2);
}

#[test]
fn aes_gcm_cross_key_decrypt_fails() {
    let key1 = [0x42u8; 16];
    let key2 = [0x43u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let ct = aes128_gcm_encrypt(&key1, &nonce, aad, plaintext).unwrap();

    assert!(aes128_gcm_decrypt(&key2, &nonce, aad, &ct).is_err());
}

#[test]
fn chacha20_poly1305_cross_key_decrypt_fails() {
    let key1 = [0x42u8; 32];
    let key2 = [0x43u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let ct = aead_encrypt(&key1, &nonce, aad, plaintext).unwrap();

    assert!(aead_decrypt(&key2, &nonce, aad, &ct).is_err());
}

#[test]
fn aes128_gcm_nist_test_case_3_with_aad() {
    let key = [
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    ];
    let nonce = [
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88,
    ];
    let pt = [
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
    ];
    let aad: &[u8] = &[];

    let ct = aes128_gcm_encrypt(&key, &nonce, aad, &pt).unwrap();
    let dec = aes128_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn aes256_gcm_nist_test_case() {
    let key = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let nonce = [0u8; 12];
    let aad: &[u8] = &[];
    let pt: &[u8] = &[];

    let ct = aes256_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
    assert_eq!(ct.len(), 16);

    let dec = aes256_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec.len(), 0);
}

#[test]
fn aes128_gcm_multi_block() {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"additional data";

    let pt: Vec<u8> = (0..256).map(|i| i as u8).collect();

    let ct = aes128_gcm_encrypt(&key, &nonce, aad, &pt).unwrap();
    let dec = aes128_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn aes256_gcm_multi_block() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"additional data";

    let pt: Vec<u8> = (0..256).map(|i| i as u8).collect();

    let ct = aes256_gcm_encrypt(&key, &nonce, aad, &pt).unwrap();
    let dec = aes256_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn chacha20_poly1305_exact_block_boundary() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"";

    let pt = [0u8; 64];
    let ct = aead_encrypt(&key, &nonce, aad, &pt).unwrap();
    let dec = aead_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn chacha20_poly1305_two_blocks() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"";

    let pt = [0u8; 128];
    let ct = aead_encrypt(&key, &nonce, aad, &pt).unwrap();
    let dec = aead_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn chacha20_poly1305_partial_block() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"";

    let pt = [0u8; 63];
    let ct = aead_encrypt(&key, &nonce, aad, &pt).unwrap();
    let dec = aead_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn aes128_gcm_boundary_15_bytes() {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"";
    let pt = [0u8; 15];

    let ct = aes128_gcm_encrypt(&key, &nonce, aad, &pt).unwrap();
    let dec = aes128_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn aes128_gcm_boundary_17_bytes() {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"";
    let pt = [0u8; 17];

    let ct = aes128_gcm_encrypt(&key, &nonce, aad, &pt).unwrap();
    let dec = aes128_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn aes128_gcm_long_aad() {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad: Vec<u8> = (0..1024).map(|i| i as u8).collect();
    let pt = b"secret";

    let ct = aes128_gcm_encrypt(&key, &nonce, &aad, pt).unwrap();
    let dec = aes128_gcm_decrypt(&key, &nonce, &aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn chacha20_poly1305_long_aad() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad: Vec<u8> = (0..1024).map(|i| i as u8).collect();
    let pt = b"secret";

    let ct = aead_encrypt(&key, &nonce, &aad, pt).unwrap();
    let dec = aead_decrypt(&key, &nonce, &aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn poly1305_empty_message() {
    let key = [0x42u8; 32];
    let tag = poly1305_mac(b"", &key);
    assert_eq!(tag.len(), 16);
}

#[test]
fn poly1305_large_message() {
    let key = [0x42u8; 32];
    let msg: Vec<u8> = (0..10000).map(|i| i as u8).collect();
    let tag = poly1305_mac(&msg, &key);
    assert_eq!(tag.len(), 16);
}

#[test]
fn chacha20_block_counter_zero() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let mut output = [0u8; 64];
    chacha20_block(&key, &nonce, 0, &mut output);
    assert!(output.iter().any(|&b| b != 0));
}

#[test]
fn chacha20_block_high_counter() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let mut output = [0u8; 64];
    chacha20_block(&key, &nonce, u32::MAX, &mut output);
    assert!(output.iter().any(|&b| b != 0));
}

#[test]
fn aes_gcm_wrong_nonce_fails() {
    let key = [0x42u8; 16];
    let nonce1 = [0x24u8; 12];
    let nonce2 = [0x25u8; 12];
    let aad = b"header";
    let pt = b"secret";

    let ct = aes128_gcm_encrypt(&key, &nonce1, aad, pt).unwrap();
    assert!(aes128_gcm_decrypt(&key, &nonce2, aad, &ct).is_err());
}

#[test]
fn chacha20_poly1305_wrong_nonce_fails() {
    let key = [0x42u8; 32];
    let nonce1 = [0x24u8; 12];
    let nonce2 = [0x25u8; 12];
    let aad = b"header";
    let pt = b"secret";

    let ct = aead_encrypt(&key, &nonce1, aad, pt).unwrap();
    assert!(aead_decrypt(&key, &nonce2, aad, &ct).is_err());
}

#[test]
fn aes128_gcm_single_byte() {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"";
    let pt = [0x42u8; 1];

    let ct = aes128_gcm_encrypt(&key, &nonce, aad, &pt).unwrap();
    let dec = aes128_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn chacha20_poly1305_single_byte() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"";
    let pt = [0x42u8; 1];

    let ct = aead_encrypt(&key, &nonce, aad, &pt).unwrap();
    let dec = aead_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn chacha20_poly1305_in_place_buffer_too_small() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";

    let mut buffer = [0u8; 10];
    let result = aead_encrypt_in_place(&key, &nonce, aad, &mut buffer, 10);
    assert!(result.is_err());
}

#[test]
fn chacha20_poly1305_in_place_decrypt_short() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";

    let mut buffer = [0u8; 15];
    let result = aead_decrypt_in_place(&key, &nonce, aad, &mut buffer, 15);
    assert!(result.is_err());
}
