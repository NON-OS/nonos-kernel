//! Cryptographic utility functions

#![no_std]

extern crate alloc;
use super::entropy::get_entropy;

/// Generate secure random u64 using hardware entropy
pub fn secure_random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    if !get_entropy(32).is_empty() {
        u64::from_le_bytes(bytes)
    } else {
        // Fallback to time-based entropy
        unsafe { core::arch::x86_64::_rdtsc() }
    }
}

/// Generate secure random u32 using hardware entropy
pub fn secure_random_u32() -> u32 {
    (secure_random_u64() >> 32) as u32
}

/// Generate secure random bytes
pub fn secure_random_bytes(buffer: &mut [u8]) {
    let entropy = get_entropy(buffer.len());
    buffer.copy_from_slice(&entropy[..buffer.len()]);
}

/// Constant-time memory comparison
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Secure memory zeroing
pub fn secure_zero(buffer: &mut [u8]) {
    unsafe {
        core::ptr::write_bytes(buffer.as_mut_ptr(), 0, buffer.len());
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}