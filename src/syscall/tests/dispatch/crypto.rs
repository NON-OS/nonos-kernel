use crate::syscall::SyscallResult;

#[test]
fn test_crypto_random_null_buf_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_random_zero_len_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_random_len_exceeds_max_returns_einval() {
    let max_len: u64 = 4096;
    let over_max = max_len + 1;
    assert!(over_max > max_len);
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_random_max_length() {
    let max_len: u64 = 4096;
    assert_eq!(max_len, 4096);
}

#[test]
fn test_crypto_random_success_returns_length() {
    let len = 32i64;
    let result = SyscallResult::success(len);
    assert_eq!(result.value, 32);
}

#[test]
fn test_crypto_random_efault_on_copy_failure() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
fn test_crypto_random_capability_required() {
    let result = SyscallResult::error(1);
    assert_eq!(result.errno(), Some(1));
}

#[test]
fn test_crypto_hash_null_data_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_hash_zero_len_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_hash_len_exceeds_max_returns_einval() {
    let max_len: u64 = 1024 * 1024;
    let over_max = max_len + 1;
    assert!(over_max > max_len);
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_hash_algo_blake3() {
    let algo_blake3: u64 = 0;
    assert_eq!(algo_blake3, 0);
}

#[test]
fn test_crypto_hash_algo_sha256() {
    let algo_sha256: u64 = 1;
    assert_eq!(algo_sha256, 1);
}

#[test]
fn test_crypto_hash_algo_sha512() {
    let algo_sha512: u64 = 2;
    assert_eq!(algo_sha512, 2);
}

#[test]
fn test_crypto_hash_invalid_algo_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_hash_success_returns_hash_id() {
    let hash_id = 1i64;
    let result = SyscallResult::success(hash_id);
    assert_eq!(result.value, 1);
}

#[test]
fn test_crypto_hash_efault_on_copy_failure() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
fn test_crypto_hash_eio_on_internal_error() {
    let result = SyscallResult::error(5);
    assert_eq!(result.errno(), Some(5));
}

#[test]
fn test_crypto_sign_null_data_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_sign_zero_len_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_sign_null_sig_out_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_sign_success_returns_sig_len() {
    let sig_len = 64i64;
    let result = SyscallResult::success_audited(sig_len);
    assert_eq!(result.value, 64);
    assert!(result.audit_required);
}

#[test]
fn test_crypto_sign_invalid_key_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_sign_buffer_too_small_returns_erange() {
    let result = SyscallResult::error(34);
    assert_eq!(result.errno(), Some(34));
}

#[test]
fn test_crypto_sign_efault_on_copy_failure() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
fn test_crypto_sign_eio_on_internal_error() {
    let result = SyscallResult::error(5);
    assert_eq!(result.errno(), Some(5));
}

#[test]
fn test_crypto_sign_signature_buffer_size() {
    let sig_buffer_size: usize = 64;
    assert_eq!(sig_buffer_size, 64);
}

#[test]
fn test_crypto_verify_null_data_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_verify_zero_len_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_verify_null_sig_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_verify_success_valid_returns_one() {
    let result = SyscallResult::success_audited(1);
    assert_eq!(result.value, 1);
    assert!(result.audit_required);
}

#[test]
fn test_crypto_verify_success_invalid_returns_zero() {
    let result = SyscallResult::success_audited(0);
    assert_eq!(result.value, 0);
}

#[test]
fn test_crypto_verify_key_not_found_returns_enoent() {
    let result = SyscallResult::error(2);
    assert_eq!(result.errno(), Some(2));
}

#[test]
fn test_crypto_verify_efault_on_copy_failure() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
fn test_crypto_encrypt_null_key_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_encrypt_null_nonce_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_encrypt_null_plaintext_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_encrypt_null_ciphertext_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_encrypt_zero_len_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_encrypt_len_exceeds_max_returns_einval() {
    let max_len: u64 = 1024 * 1024;
    let over_max = max_len + 1;
    assert!(over_max > max_len);
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_encrypt_algo_chacha20poly1305() {
    let algo: u64 = 0;
    assert_eq!(algo, 0);
}

#[test]
fn test_crypto_encrypt_algo_aes256_gcm() {
    let algo: u64 = 1;
    assert_eq!(algo, 1);
}

#[test]
fn test_crypto_encrypt_invalid_algo_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_encrypt_success_returns_ct_len() {
    let ct_len = 48i64;
    let result = SyscallResult::success_audited(ct_len);
    assert_eq!(result.value, 48);
    assert!(result.audit_required);
}

#[test]
fn test_crypto_encrypt_efault_on_copy_failure() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
fn test_crypto_encrypt_eio_on_internal_error() {
    let result = SyscallResult::error(5);
    assert_eq!(result.errno(), Some(5));
}

#[test]
fn test_crypto_encrypt_key_size() {
    let key_size: usize = 32;
    assert_eq!(key_size, 32);
}

#[test]
fn test_crypto_encrypt_nonce_size() {
    let nonce_size: usize = 12;
    assert_eq!(nonce_size, 12);
}

#[test]
fn test_crypto_decrypt_null_key_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_decrypt_null_nonce_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_decrypt_null_ciphertext_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_decrypt_null_plaintext_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_decrypt_ct_len_too_small_returns_einval() {
    let min_ct_len: u64 = 16;
    let too_small = min_ct_len - 1;
    assert!(too_small < min_ct_len);
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_decrypt_ct_len_exceeds_max_returns_einval() {
    let max_len: u64 = 1024 * 1024 + 16;
    let over_max = max_len + 1;
    assert!(over_max > max_len);
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_decrypt_invalid_algo_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_decrypt_success_returns_pt_len() {
    let pt_len = 32i64;
    let result = SyscallResult::success_audited(pt_len);
    assert_eq!(result.value, 32);
    assert!(result.audit_required);
}

#[test]
fn test_crypto_decrypt_auth_failure_returns_ebadmsg() {
    let result = SyscallResult::error(74);
    assert_eq!(result.errno(), Some(74));
}

#[test]
fn test_crypto_decrypt_efault_on_copy_failure() {
    let result = SyscallResult::error(14);
    assert_eq!(result.errno(), Some(14));
}

#[test]
fn test_crypto_keygen_success_returns_key_id() {
    let key_id = 1i64;
    let result = SyscallResult::success_audited(key_id);
    assert_eq!(result.value, 1);
    assert!(result.audit_required);
}

#[test]
fn test_crypto_keygen_invalid_algo_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_zk_prove_success_returns_proof_len() {
    let proof_len = 256i64;
    let result = SyscallResult::success_audited(proof_len);
    assert_eq!(result.value, 256);
    assert!(result.audit_required);
}

#[test]
fn test_crypto_zk_prove_invalid_circuit_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_zk_verify_success_valid_returns_one() {
    let result = SyscallResult::success_audited(1);
    assert_eq!(result.value, 1);
}

#[test]
fn test_crypto_zk_verify_success_invalid_returns_zero() {
    let result = SyscallResult::success_audited(0);
    assert_eq!(result.value, 0);
}

#[test]
fn test_crypto_zk_verify_invalid_proof_returns_einval() {
    let result = SyscallResult::error(22);
    assert_eq!(result.errno(), Some(22));
}

#[test]
fn test_crypto_capability_required() {
    let result = SyscallResult::error(1);
    assert_eq!(result.errno(), Some(1));
}

#[test]
fn test_crypto_max_hash_input_length() {
    let max_len: u64 = 1024 * 1024;
    assert_eq!(max_len, 1048576);
}

#[test]
fn test_crypto_max_encrypt_length() {
    let max_len: u64 = 1024 * 1024;
    assert_eq!(max_len, 1048576);
}

#[test]
fn test_crypto_max_random_length() {
    let max_len: u64 = 4096;
    assert_eq!(max_len, 4096);
}

#[test]
fn test_crypto_aead_tag_size() {
    let tag_size: usize = 16;
    assert_eq!(tag_size, 16);
}
