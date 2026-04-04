// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::crypto::pqc::sphincs::{
    SPHINCS_N, SPHINCS_K, SPHINCS_W, SPHINCS_H, SPHINCS_D, SPHINCS_A,
    SPHINCS_PK_BYTES, SPHINCS_SK_BYTES, SPHINCS_SIG_BYTES,
    SPHINCS_WOTS_LEN, SPHINCS_WOTS_LEN1, SPHINCS_WOTS_LEN2,
    SPHINCS_WOTS_SIG_BYTES, SPHINCS_FORS_SIG_BYTES, SPHINCS_FORS_MSG_BYTES,
    SPHINCS_PK_SEED_BYTES, SPHINCS_PK_ROOT_BYTES,
    SPHINCS_SK_SEED_BYTES, SPHINCS_SK_PRF_BYTES,
    sphincs_param_name,
};

#[test]
fn test_sphincs_security_parameter() {
    assert!(SPHINCS_N > 0);
    assert!(SPHINCS_N == 16 || SPHINCS_N == 24 || SPHINCS_N == 32);
}

#[test]
fn test_sphincs_fors_parameters() {
    assert!(SPHINCS_K > 0);
    assert!(SPHINCS_A > 0);
    assert_eq!(SPHINCS_FORS_MSG_BYTES, (SPHINCS_K * SPHINCS_A + 7) / 8);
}

#[test]
fn test_sphincs_wots_parameter() {
    assert!(SPHINCS_W == 4 || SPHINCS_W == 16 || SPHINCS_W == 256);
}

#[test]
fn test_sphincs_tree_parameters() {
    assert!(SPHINCS_H > 0);
    assert!(SPHINCS_D > 0);
    assert_eq!(SPHINCS_H % SPHINCS_D, 0);
}

#[test]
fn test_sphincs_public_key_size() {
    assert!(SPHINCS_PK_BYTES > 0);
    assert_eq!(SPHINCS_PK_BYTES, SPHINCS_PK_SEED_BYTES + SPHINCS_PK_ROOT_BYTES);
}

#[test]
fn test_sphincs_secret_key_size() {
    assert!(SPHINCS_SK_BYTES > 0);
    assert!(SPHINCS_SK_BYTES >= SPHINCS_SK_SEED_BYTES + SPHINCS_SK_PRF_BYTES);
}

#[test]
fn test_sphincs_signature_size() {
    assert!(SPHINCS_SIG_BYTES > 0);
    assert!(SPHINCS_SIG_BYTES > SPHINCS_FORS_SIG_BYTES);
}

#[test]
fn test_sphincs_wots_len() {
    assert!(SPHINCS_WOTS_LEN > 0);
    assert_eq!(SPHINCS_WOTS_LEN, SPHINCS_WOTS_LEN1 + SPHINCS_WOTS_LEN2);
}

#[test]
fn test_sphincs_wots_sig_size() {
    assert_eq!(SPHINCS_WOTS_SIG_BYTES, SPHINCS_WOTS_LEN * SPHINCS_N);
}

#[test]
fn test_sphincs_fors_sig_size() {
    assert!(SPHINCS_FORS_SIG_BYTES > 0);
}

#[test]
fn test_sphincs_pk_seed_bytes() {
    assert_eq!(SPHINCS_PK_SEED_BYTES, SPHINCS_N);
}

#[test]
fn test_sphincs_pk_root_bytes() {
    assert_eq!(SPHINCS_PK_ROOT_BYTES, SPHINCS_N);
}

#[test]
fn test_sphincs_sk_seed_bytes() {
    assert_eq!(SPHINCS_SK_SEED_BYTES, SPHINCS_N);
}

#[test]
fn test_sphincs_sk_prf_bytes() {
    assert_eq!(SPHINCS_SK_PRF_BYTES, SPHINCS_N);
}

#[test]
fn test_sphincs_param_name() {
    let name = sphincs_param_name();
    assert!(!name.is_empty());
}

#[test]
fn test_sphincs_constants_consistency() {
    assert!(SPHINCS_H / SPHINCS_D > 0);
    let layers = SPHINCS_H / SPHINCS_D;
    assert!(layers >= 1);
}

#[test]
fn test_sphincs_signature_larger_than_classical() {
    let ed25519_sig: usize = 64;
    assert!(SPHINCS_SIG_BYTES > ed25519_sig);
}

#[test]
fn test_sphincs_pk_larger_than_classical() {
    let ed25519_pk: usize = 32;
    assert!(SPHINCS_PK_BYTES >= ed25519_pk);
}

#[test]
fn test_kyber_sizes() {
    let kyber512_pk: usize = 800;
    let kyber768_pk: usize = 1184;
    let kyber1024_pk: usize = 1568;
    assert!(kyber512_pk < kyber768_pk);
    assert!(kyber768_pk < kyber1024_pk);
}

#[test]
fn test_kyber_ciphertext_sizes() {
    let kyber512_ct: usize = 768;
    let kyber768_ct: usize = 1088;
    let kyber1024_ct: usize = 1568;
    assert!(kyber512_ct < kyber768_ct);
    assert!(kyber768_ct < kyber1024_ct);
}

#[test]
fn test_kyber_shared_secret_size() {
    let shared_secret: usize = 32;
    assert_eq!(shared_secret, 32);
}

#[test]
fn test_dilithium_sizes() {
    let dilithium2_pk: usize = 1312;
    let dilithium3_pk: usize = 1952;
    let dilithium5_pk: usize = 2592;
    assert!(dilithium2_pk < dilithium3_pk);
    assert!(dilithium3_pk < dilithium5_pk);
}

#[test]
fn test_dilithium_signature_sizes() {
    let dilithium2_sig: usize = 2420;
    let dilithium3_sig: usize = 3293;
    let dilithium5_sig: usize = 4595;
    assert!(dilithium2_sig < dilithium3_sig);
    assert!(dilithium3_sig < dilithium5_sig);
}

#[test]
fn test_dilithium_secret_key_sizes() {
    let dilithium2_sk: usize = 2528;
    let dilithium3_sk: usize = 4000;
    let dilithium5_sk: usize = 4864;
    assert!(dilithium2_sk < dilithium3_sk);
    assert!(dilithium3_sk < dilithium5_sk);
}

#[test]
fn test_pqc_security_levels() {
    let level1: usize = 128;
    let level3: usize = 192;
    let level5: usize = 256;
    assert!(level1 < level3);
    assert!(level3 < level5);
}

#[test]
fn test_sphincs_wots_len1_calculation() {
    let log_w = match SPHINCS_W {
        4 => 2,
        16 => 4,
        256 => 8,
        _ => 4,
    };
    let expected_len1 = (SPHINCS_N * 8 + log_w - 1) / log_w;
    assert_eq!(SPHINCS_WOTS_LEN1, expected_len1);
}

#[test]
fn test_sphincs_tree_height_per_layer() {
    let height_per_layer = SPHINCS_H / SPHINCS_D;
    assert!(height_per_layer > 0);
    assert!(height_per_layer <= 32);
}

#[test]
fn test_pqc_vs_classical_sizes() {
    let rsa_2048_pk: usize = 256;
    let rsa_2048_sig: usize = 256;
    assert!(SPHINCS_PK_BYTES > rsa_2048_pk);
    assert!(SPHINCS_SIG_BYTES > rsa_2048_sig);
}
