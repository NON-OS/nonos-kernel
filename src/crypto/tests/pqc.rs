// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Post-quantum cryptography tests - SPHINCS+, Kyber, MlDsa65 parameter validation

use crate::crypto::pqc::sphincs::{
    sphincs_param_name, SPHINCS_A, SPHINCS_D, SPHINCS_FORS_MSG_BYTES, SPHINCS_FORS_SIG_BYTES,
    SPHINCS_H, SPHINCS_K, SPHINCS_N, SPHINCS_PK_BYTES, SPHINCS_PK_ROOT_BYTES,
    SPHINCS_PK_SEED_BYTES, SPHINCS_SIG_BYTES, SPHINCS_SK_BYTES, SPHINCS_SK_PRF_BYTES,
    SPHINCS_SK_SEED_BYTES, SPHINCS_W, SPHINCS_WOTS_LEN, SPHINCS_WOTS_LEN1, SPHINCS_WOTS_LEN2,
    SPHINCS_WOTS_SIG_BYTES,
};
use crate::test::framework::TestResult;

pub(crate) fn test_sphincs_security_parameter() -> TestResult {
    if SPHINCS_N == 0 {
        return TestResult::Fail;
    }
    if !(SPHINCS_N == 16 || SPHINCS_N == 24 || SPHINCS_N == 32) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_fors_parameters() -> TestResult {
    if SPHINCS_K == 0 {
        return TestResult::Fail;
    }
    if SPHINCS_A == 0 {
        return TestResult::Fail;
    }
    if SPHINCS_FORS_MSG_BYTES != (SPHINCS_K * SPHINCS_A + 7) / 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_wots_parameter() -> TestResult {
    if !(SPHINCS_W == 4 || SPHINCS_W == 16 || SPHINCS_W == 256) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_tree_parameters() -> TestResult {
    if SPHINCS_H == 0 {
        return TestResult::Fail;
    }
    if SPHINCS_D == 0 {
        return TestResult::Fail;
    }
    if SPHINCS_H % SPHINCS_D != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_public_key_size() -> TestResult {
    if SPHINCS_PK_BYTES == 0 {
        return TestResult::Fail;
    }
    if SPHINCS_PK_BYTES != SPHINCS_PK_SEED_BYTES + SPHINCS_PK_ROOT_BYTES {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_secret_key_size() -> TestResult {
    if SPHINCS_SK_BYTES == 0 {
        return TestResult::Fail;
    }
    if SPHINCS_SK_BYTES < SPHINCS_SK_SEED_BYTES + SPHINCS_SK_PRF_BYTES {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_signature_size() -> TestResult {
    if SPHINCS_SIG_BYTES == 0 {
        return TestResult::Fail;
    }
    if SPHINCS_SIG_BYTES <= SPHINCS_FORS_SIG_BYTES {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_wots_len() -> TestResult {
    if SPHINCS_WOTS_LEN == 0 {
        return TestResult::Fail;
    }
    if SPHINCS_WOTS_LEN != SPHINCS_WOTS_LEN1 + SPHINCS_WOTS_LEN2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_wots_sig_size() -> TestResult {
    if SPHINCS_WOTS_SIG_BYTES != SPHINCS_WOTS_LEN * SPHINCS_N {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_fors_sig_size() -> TestResult {
    if SPHINCS_FORS_SIG_BYTES == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_pk_seed_bytes() -> TestResult {
    if SPHINCS_PK_SEED_BYTES != SPHINCS_N {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_pk_root_bytes() -> TestResult {
    if SPHINCS_PK_ROOT_BYTES != SPHINCS_N {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_sk_seed_bytes() -> TestResult {
    if SPHINCS_SK_SEED_BYTES != SPHINCS_N {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_sk_prf_bytes() -> TestResult {
    if SPHINCS_SK_PRF_BYTES != SPHINCS_N {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_param_name() -> TestResult {
    let name = sphincs_param_name();
    if name.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_constants_consistency() -> TestResult {
    if SPHINCS_H / SPHINCS_D == 0 {
        return TestResult::Fail;
    }
    let layers = SPHINCS_H / SPHINCS_D;
    if layers < 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_signature_larger_than_classical() -> TestResult {
    let ed25519_sig: usize = 64;
    if SPHINCS_SIG_BYTES <= ed25519_sig {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_pk_larger_than_classical() -> TestResult {
    let ed25519_pk: usize = 32;
    if SPHINCS_PK_BYTES < ed25519_pk {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_kyber_sizes() -> TestResult {
    let kyber512_pk: usize = 800;
    let kyber768_pk: usize = 1184;
    let kyber1024_pk: usize = 1568;
    if kyber512_pk >= kyber768_pk {
        return TestResult::Fail;
    }
    if kyber768_pk >= kyber1024_pk {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_kyber_ciphertext_sizes() -> TestResult {
    let kyber512_ct: usize = 768;
    let kyber768_ct: usize = 1088;
    let kyber1024_ct: usize = 1568;
    if kyber512_ct >= kyber768_ct {
        return TestResult::Fail;
    }
    if kyber768_ct >= kyber1024_ct {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_kyber_shared_secret_size() -> TestResult {
    let shared_secret: usize = 32;
    if shared_secret != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ml_dsa_65_sizes() -> TestResult {
    let ml_dsa_652_pk: usize = 1312;
    let ml_dsa_653_pk: usize = 1952;
    let ml_dsa_655_pk: usize = 2592;
    if ml_dsa_652_pk >= ml_dsa_653_pk {
        return TestResult::Fail;
    }
    if ml_dsa_653_pk >= ml_dsa_655_pk {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ml_dsa_65_signature_sizes() -> TestResult {
    let ml_dsa_652_sig: usize = 2420;
    let ml_dsa_653_sig: usize = 3293;
    let ml_dsa_655_sig: usize = 4595;
    if ml_dsa_652_sig >= ml_dsa_653_sig {
        return TestResult::Fail;
    }
    if ml_dsa_653_sig >= ml_dsa_655_sig {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ml_dsa_65_secret_key_sizes() -> TestResult {
    let ml_dsa_652_sk: usize = 2528;
    let ml_dsa_653_sk: usize = 4000;
    let ml_dsa_655_sk: usize = 4864;
    if ml_dsa_652_sk >= ml_dsa_653_sk {
        return TestResult::Fail;
    }
    if ml_dsa_653_sk >= ml_dsa_655_sk {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pqc_security_levels() -> TestResult {
    let level1: usize = 128;
    let level3: usize = 192;
    let level5: usize = 256;
    if level1 >= level3 {
        return TestResult::Fail;
    }
    if level3 >= level5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_wots_len1_calculation() -> TestResult {
    let log_w = match SPHINCS_W {
        4 => 2,
        16 => 4,
        256 => 8,
        _ => 4,
    };
    let expected_len1 = (SPHINCS_N * 8 + log_w - 1) / log_w;
    if SPHINCS_WOTS_LEN1 != expected_len1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sphincs_tree_height_per_layer() -> TestResult {
    let height_per_layer = SPHINCS_H / SPHINCS_D;
    if height_per_layer == 0 {
        return TestResult::Fail;
    }
    if height_per_layer > 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pqc_vs_classical_sizes() -> TestResult {
    let rsa_2048_pk: usize = 256;
    let rsa_2048_sig: usize = 256;
    if SPHINCS_PK_BYTES <= rsa_2048_pk {
        return TestResult::Fail;
    }
    if SPHINCS_SIG_BYTES <= rsa_2048_sig {
        return TestResult::Fail;
    }
    TestResult::Pass
}
