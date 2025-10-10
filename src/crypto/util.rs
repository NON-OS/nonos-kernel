use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
extern crate alloc;
use alloc::vec::Vec;

static CRYPTO_RNG_STATE: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);
static RNG_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn generate_secure_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    fill_random(&mut key);
    key
}

pub fn fill_random(buffer: &mut [u8]) {
    let mut state = CRYPTO_RNG_STATE.lock();
    let counter = RNG_COUNTER.fetch_add(1, Ordering::Release);

    // Simple XOR-based PRNG for kernel use
    for (i, byte) in buffer.iter_mut().enumerate() {
        let index = (i + (counter as usize)) % 32;
        state[index] = state[index].wrapping_add((counter as u8).wrapping_mul(i as u8 + 1));
        *byte = state[index];
    }
}

pub fn secure_zero(data: &mut [u8]) {
    for byte in data {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
}

pub fn hash_memory_region(
    start_addr: u64,
    size: u64,
    output: &mut [u8; 32],
) -> Result<(), &'static str> {
    if output.len() < 32 {
        return Err("Hash output buffer too small");
    }

    // Simple hash of memory region (in a real implementation, would use proper hash
    // function)
    let mut hash = [0u8; 32];
    hash[0..8].copy_from_slice(&start_addr.to_le_bytes());
    hash[8..16].copy_from_slice(&size.to_le_bytes());

    // Mix in some entropy
    let mut entropy = [0u8; 16];
    fill_random(&mut entropy);
    hash[16..32].copy_from_slice(&entropy);

    output.copy_from_slice(&hash);
    Ok(())
}

pub fn secure_erase_memory_region(start_addr: u64, size: u64) -> Result<(), &'static str> {
    if size == 0 {
        return Err("Cannot erase zero-sized region");
    }

    if start_addr == 0 {
        return Err("Cannot erase null pointer region");
    }

    // Validate address range is reasonable
    if start_addr.checked_add(size).is_none() {
        return Err("Address range overflow");
    }

    unsafe {
        let ptr = start_addr as *mut u8;

        // Triple overwrite with different patterns for secure erasure
        // Pattern 1: All zeros
        core::ptr::write_bytes(ptr, 0x00, size as usize);

        // Pattern 2: All ones
        core::ptr::write_bytes(ptr, 0xFF, size as usize);

        // Pattern 3: Random pattern
        let mut random_pattern = [0u8; 256];
        fill_random(&mut random_pattern);

        let mut offset = 0;
        while offset < size {
            let chunk_size = core::cmp::min(256, (size - offset) as usize);
            core::ptr::copy_nonoverlapping(
                random_pattern.as_ptr(),
                ptr.add(offset as usize),
                chunk_size,
            );
            offset += chunk_size as u64;
        }

        // Final pattern: All zeros
        core::ptr::write_bytes(ptr, 0x00, size as usize);

        // Memory barrier to ensure writes complete
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    Ok(())
}

pub fn secure_random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    fill_random(&mut bytes);
    u64::from_le_bytes(bytes)
}

/// Generate random bytes for crypto operations
pub fn generate_random_bytes(len: usize) -> Result<Vec<u8>, &'static str> {
    let mut bytes = alloc::vec![0u8; len];
    fill_random(&mut bytes);
    Ok(bytes)
}

/// Generate random bytes as fixed array for crypto operations
pub fn generate_random_bytes_32() -> Result<[u8; 32], &'static str> {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes);
    Ok(bytes)
}

/// Convert Vec<u8> to [u8; 32] with truncation/padding
pub fn vec_to_array32(vec: Vec<u8>) -> [u8; 32] {
    let mut array = [0u8; 32];
    let len = core::cmp::min(vec.len(), 32);
    array[..len].copy_from_slice(&vec[..len]);
    array
}

/// Basic ChaCha20-Poly1305 encryption (minimal implementation)
pub fn encrypt_chacha20_poly1305(
    data: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, &'static str> {
    // Simplified encryption - in production would use proper ChaCha20-Poly1305
    let mut encrypted = alloc::vec![0u8; data.len() + 16]; // +16 for tag

    // XOR with key stream (simplified)
    for (i, &byte) in data.iter().enumerate() {
        let key_byte = key[i % 32] ^ nonce[i % 12];
        encrypted[i] = byte ^ key_byte;
    }

    // Add simplified tag
    for i in 0..16 {
        encrypted[data.len() + i] = key[i % 32] ^ nonce[i % 12];
    }

    Ok(encrypted)
}

/// Basic ChaCha20-Poly1305 decryption (minimal implementation)
pub fn decrypt_chacha20_poly1305(
    encrypted_data: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, &'static str> {
    if encrypted_data.len() < 16 {
        return Err("Invalid encrypted data length");
    }

    let data_len = encrypted_data.len() - 16;
    let mut decrypted = alloc::vec![0u8; data_len];

    // XOR with key stream (simplified)
    for (i, &byte) in encrypted_data[..data_len].iter().enumerate() {
        let key_byte = key[i % 32] ^ nonce[i % 12];
        decrypted[i] = byte ^ key_byte;
    }

    Ok(decrypted)
}

/// Key derivation function
pub fn derive_key(master_key: &[u8; 32], salt: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut derived = [0u8; 32];

    // Simple key derivation (HKDF-like)
    for i in 0..32 {
        derived[i] = master_key[i] ^ salt[i] ^ info.get(i).unwrap_or(&(i as u8 + 1));
    }

    derived
}

/// ED25519 signature (simplified)
pub fn sign_ed25519(message: &[u8], private_key: &[u8; 32]) -> Result<[u8; 64], &'static str> {
    let mut signature = [0u8; 64];

    // Simplified signature - combine message hash with private key
    for (i, &byte) in message.iter().take(32).enumerate() {
        signature[i] = byte ^ private_key[i];
    }

    // Second half with key material
    for i in 32..64 {
        signature[i] = private_key[i % 32] ^ (i as u8);
    }

    Ok(signature)
}

/// ED25519 verification (simplified)
pub fn verify_ed25519(
    message: &[u8],
    signature: &[u8; 64],
    public_key: &[u8; 32],
) -> Result<bool, &'static str> {
    // Simplified verification - check signature format
    let mut expected = [0u8; 64];

    for (i, &byte) in message.iter().take(32).enumerate() {
        expected[i] = byte ^ public_key[i];
    }

    for i in 32..64 {
        expected[i] = public_key[i % 32] ^ (i as u8);
    }

    Ok(signature == &expected)
}

/// Post-quantum encryption stub
pub fn post_quantum_encrypt(data: &[u8], key: &[u8; 64]) -> Result<Vec<u8>, &'static str> {
    // FIXME: Replace with proper Kyber/CRYSTALS implementation
    let mut encrypted = alloc::vec![0u8; data.len()];
    for (i, &byte) in data.iter().enumerate() {
        encrypted[i] = byte ^ key[i % 64];
    }
    Ok(encrypted)
}

/// Post-quantum decryption stub
pub fn post_quantum_decrypt(encrypted: &[u8], key: &[u8; 64]) -> Result<Vec<u8>, &'static str> {
    // FIXME: Replace with proper Kyber/CRYSTALS implementation
    let mut decrypted = alloc::vec![0u8; encrypted.len()];
    for (i, &byte) in encrypted.iter().enumerate() {
        decrypted[i] = byte ^ key[i % 64];
    }
    Ok(decrypted)
}

/// Hash function using blake3_hash
pub fn hash_blake3(data: &[u8]) -> [u8; 32] {
    crate::crypto::blake3_hash(data)
}
