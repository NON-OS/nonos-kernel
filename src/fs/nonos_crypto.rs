// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Encrypted filesystem layer using ChaCha20-Poly1305 AEAD.
//!
//! This module provides a secure, encrypted file storage system with:
//! - Per-file encryption keys derived from path + random salt
//! - ChaCha20-Poly1305 authenticated encryption
//! - Secure memory zeroization on delete
//! - Counter-based nonces for uniqueness guarantees

#![no_std]

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec::Vec, string::ToString};
use core::sync::atomic::{AtomicU64, Ordering, compiler_fence};
use spin::{RwLock, Once};

// Use ChaCha20-Poly1305 AEAD from crypto module
use crate::crypto::chacha20poly1305::{aead_encrypt, aead_decrypt};
use crate::crypto::rng::fill_random_bytes;
use crate::crypto::hash::sha256;

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

/// Nonce size for ChaCha20-Poly1305 (96 bits = 12 bytes, RFC 8439)
pub const NONCE_SIZE: usize = 12;

/// Authentication tag size (128 bits = 16 bytes)
pub const TAG_SIZE: usize = 16;

/// Salt size for key derivation (128 bits = 16 bytes)
pub const SALT_SIZE: usize = 16;

/// Encryption key size (256 bits = 32 bytes)
pub const KEY_SIZE: usize = 32;

/// Maximum file size for encrypted storage (64 MiB)
pub const MAX_ENCRYPTED_FILE_SIZE: usize = 64 * 1024 * 1024;

/// Maximum path length
pub const MAX_PATH_LEN: usize = 4096;

/// Key derivation domain separator
const KEY_DERIVATION_CONTEXT: &[u8] = b"NONOS_CRYPTOFS_KEY_V1";

/// AEAD associated data for file encryption
const FILE_AAD: &[u8] = b"NONOS_CRYPTOFS_FILE";

// ============================================================================
// STRUCTURED ERROR HANDLING
// ============================================================================

/// CryptoFS operation errors with detailed messages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoFsError {
    /// CryptoFS not initialized
    NotInitialized,
    /// File not found
    NotFound,
    /// File already exists
    AlreadyExists,
    /// Path too long
    PathTooLong,
    /// Invalid path (empty or invalid characters)
    InvalidPath,
    /// Encrypted data too short (missing nonce/tag)
    DataTooShort,
    /// Encrypted data corrupted or tampered
    DecryptionFailed,
    /// Encryption operation failed
    EncryptionFailed,
    /// File too large
    FileTooLarge,
    /// Authentication tag verification failed
    AuthenticationFailed,
    /// Random number generation failed
    RngFailed,
    /// Out of memory
    OutOfMemory,
    /// Nonce counter overflow (requires key rotation)
    NonceExhausted,
    /// Internal error
    InternalError(&'static str),
}

impl CryptoFsError {
    /// Convert to errno-style negative integer
    pub const fn to_errno(self) -> i32 {
        match self {
            CryptoFsError::NotInitialized => -5,     // EIO
            CryptoFsError::NotFound => -2,           // ENOENT
            CryptoFsError::AlreadyExists => -17,     // EEXIST
            CryptoFsError::PathTooLong => -36,       // ENAMETOOLONG
            CryptoFsError::InvalidPath => -22,       // EINVAL
            CryptoFsError::DataTooShort => -22,      // EINVAL
            CryptoFsError::DecryptionFailed => -5,   // EIO
            CryptoFsError::EncryptionFailed => -5,   // EIO
            CryptoFsError::FileTooLarge => -27,      // EFBIG
            CryptoFsError::AuthenticationFailed => -5, // EIO
            CryptoFsError::RngFailed => -5,          // EIO
            CryptoFsError::OutOfMemory => -12,       // ENOMEM
            CryptoFsError::NonceExhausted => -5,     // EIO
            CryptoFsError::InternalError(_) => -5,   // EIO
        }
    }

    /// Get human-readable error message
    pub const fn as_str(self) -> &'static str {
        match self {
            CryptoFsError::NotInitialized => "CryptoFS not initialized",
            CryptoFsError::NotFound => "File not found",
            CryptoFsError::AlreadyExists => "File already exists",
            CryptoFsError::PathTooLong => "Path too long",
            CryptoFsError::InvalidPath => "Invalid path",
            CryptoFsError::DataTooShort => "Encrypted data too short",
            CryptoFsError::DecryptionFailed => "Decryption failed",
            CryptoFsError::EncryptionFailed => "Encryption failed",
            CryptoFsError::FileTooLarge => "File too large",
            CryptoFsError::AuthenticationFailed => "Authentication failed",
            CryptoFsError::RngFailed => "Random generation failed",
            CryptoFsError::OutOfMemory => "Out of memory",
            CryptoFsError::NonceExhausted => "Nonce counter exhausted",
            CryptoFsError::InternalError(msg) => msg,
        }
    }
}

impl From<CryptoFsError> for &'static str {
    fn from(err: CryptoFsError) -> Self {
        err.as_str()
    }
}

/// Result type for CryptoFS operations
pub type CryptoResult<T> = Result<T, CryptoFsError>;

// ============================================================================
// STATISTICS
// ============================================================================

/// CryptoFS statistics for monitoring and debugging
#[derive(Debug, Default, Clone)]
pub struct CryptoFsStatistics {
    /// Number of files currently stored
    pub files: u64,
    /// Total bytes of plaintext stored (before encryption)
    pub bytes_stored: u64,
    /// Number of encryption operations performed
    pub encryptions: u64,
    /// Number of decryption operations performed
    pub decryptions: u64,
    /// Number of failed decryption attempts (potential tampering)
    pub decryption_failures: u64,
    /// Number of files securely deleted
    pub secure_deletes: u64,
    /// Current nonce counter value
    pub nonce_counter: u64,
}

// ============================================================================
// SECURE MEMORY OPERATIONS
// ============================================================================

/// Securely zeroize a byte slice, preventing compiler optimization
#[inline]
fn secure_zeroize(data: &mut [u8]) {
    for byte in data.iter_mut() {
        // Use volatile write to prevent optimization
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    // Memory fence to ensure writes complete
    compiler_fence(Ordering::SeqCst);
}

/// Securely zeroize a fixed-size array
#[inline]
fn secure_zeroize_array<const N: usize>(data: &mut [u8; N]) {
    secure_zeroize(data.as_mut_slice());
}

// ============================================================================
// FILE ENTRY STRUCTURE
// ============================================================================

/// Internal file entry with encryption metadata
#[derive(Debug)]
struct FileEntry {
    /// Unique inode number
    inode: u64,
    /// 32-byte encryption key derived from path + random salt
    key: [u8; KEY_SIZE],
    /// Random salt used in key derivation
    salt: [u8; SALT_SIZE],
    /// Encrypted data: nonce (12 bytes) || ciphertext || tag (16 bytes)
    encrypted: Vec<u8>,
    /// Creation timestamp (ticks)
    created_at: u64,
    /// Last modification timestamp (ticks)
    modified_at: u64,
}

impl FileEntry {
    /// Create new file entry with random salt
    fn new(inode: u64, path: &str) -> CryptoResult<Self> {
        let mut salt = [0u8; SALT_SIZE];
        fill_random_bytes(&mut salt);

        let key = derive_key(path, &salt);
        let now = crate::sys::timer::ticks();

        Ok(Self {
            inode,
            key,
            salt,
            encrypted: Vec::new(),
            created_at: now,
            modified_at: now,
        })
    }

    /// Securely clear all sensitive data
    fn secure_clear(&mut self) {
        secure_zeroize(&mut self.encrypted);
        secure_zeroize_array(&mut self.key);
        secure_zeroize_array(&mut self.salt);
        self.encrypted.clear();
    }

    /// Get plaintext size from encrypted size
    fn plaintext_size(&self) -> usize {
        if self.encrypted.len() < NONCE_SIZE + TAG_SIZE {
            0
        } else {
            self.encrypted.len() - NONCE_SIZE - TAG_SIZE
        }
    }
}

impl Clone for FileEntry {
    fn clone(&self) -> Self {
        Self {
            inode: self.inode,
            key: self.key,
            salt: self.salt,
            encrypted: self.encrypted.clone(),
            created_at: self.created_at,
            modified_at: self.modified_at,
        }
    }
}

impl Drop for FileEntry {
    fn drop(&mut self) {
        // Ensure sensitive data is zeroized on drop
        self.secure_clear();
    }
}

// ============================================================================
// CRYPTO FILESYSTEM INTERNALS
// ============================================================================

/// Internal state protected by RwLock
struct CryptoInner {
    /// Block size for storage calculations
    block_size: usize,
    /// Total available blocks
    total_blocks: usize,
    /// File storage map (path -> entry)
    files: BTreeMap<String, FileEntry>,
    /// Next inode number
    next_inode: AtomicU64,
    /// Global nonce counter for unique nonces
    nonce_counter: AtomicU64,
}

impl core::fmt::Debug for CryptoInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CryptoInner")
            .field("block_size", &self.block_size)
            .field("total_blocks", &self.total_blocks)
            .field("files_count", &self.files.len())
            .field("next_inode", &self.next_inode.load(Ordering::Relaxed))
            .field("nonce_counter", &self.nonce_counter.load(Ordering::Relaxed))
            .finish()
    }
}

// ============================================================================
// CRYPTO FILESYSTEM
// ============================================================================

/// Encrypted filesystem with ChaCha20-Poly1305 AEAD
#[derive(Debug)]
pub struct CryptoFileSystem {
    /// Inner state protected by RwLock for concurrent read access
    inner: RwLock<CryptoInner>,
    /// Statistics (separate lock for non-blocking stats updates)
    stats: RwLock<CryptoFsStatistics>,
}

impl CryptoFileSystem {
    /// Create a new CryptoFileSystem
    fn new(total_blocks: usize, block_size: usize) -> Self {
        Self {
            inner: RwLock::new(CryptoInner {
                block_size,
                total_blocks,
                files: BTreeMap::new(),
                next_inode: AtomicU64::new(3), // 0,1,2 reserved
                nonce_counter: AtomicU64::new(0),
            }),
            stats: RwLock::new(CryptoFsStatistics::default()),
        }
    }

    /// Sync all pending operations (no-op for in-memory FS)
    pub fn sync_all(&self) {
        // RAM-based filesystem has no pending I/O
    }

    /// Process pending background operations
    pub fn process_pending_operations(&self, _max_ops: usize) -> usize {
        0 // No background operations
    }

    /// Get current statistics (read-only, non-blocking)
    pub fn stats(&self) -> CryptoFsStatistics {
        let stats = self.stats.read();
        let mut result = stats.clone();

        // Add current nonce counter
        let inner = self.inner.read();
        result.nonce_counter = inner.nonce_counter.load(Ordering::Relaxed);
        result
    }

    /// Check if a file exists
    pub fn exists(&self, path: &str) -> bool {
        let inner = self.inner.read();
        inner.files.contains_key(path)
    }

    /// Get file metadata
    pub fn get_file_info(&self, path: &str) -> CryptoResult<FileInfo> {
        let inner = self.inner.read();
        let entry = inner.files.get(path).ok_or(CryptoFsError::NotFound)?;

        Ok(FileInfo {
            inode: entry.inode,
            size: entry.plaintext_size(),
            encrypted_size: entry.encrypted.len(),
            created: entry.created_at,
            modified: entry.modified_at,
        })
    }

    /// List all file paths
    pub fn list_files(&self) -> Vec<String> {
        let inner = self.inner.read();
        inner.files.keys().cloned().collect()
    }

    /// Get total storage used
    pub fn storage_used(&self) -> usize {
        let inner = self.inner.read();
        inner.files.values().map(|e| e.encrypted.len()).sum()
    }

    /// Generate next unique nonce
    fn next_nonce(&self) -> CryptoResult<[u8; NONCE_SIZE]> {
        let inner = self.inner.read();
        let counter = inner.nonce_counter.fetch_add(1, Ordering::SeqCst);

        // Check for counter overflow (would compromise security)
        if counter == u64::MAX {
            return Err(CryptoFsError::NonceExhausted);
        }

        Ok(generate_nonce(counter))
    }
}

/// Public file information
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub inode: u64,
    pub size: usize,
    pub encrypted_size: usize,
    pub created: u64,
    pub modified: u64,
}

// ============================================================================
// GLOBAL INSTANCE
// ============================================================================

static CRYPTOFS: Once<CryptoFileSystem> = Once::new();

/// Initialize the CryptoFS subsystem
pub fn init_cryptofs(total_blocks: usize, block_size: usize) -> CryptoResult<()> {
    CRYPTOFS.call_once(|| CryptoFileSystem::new(total_blocks, block_size));
    Ok(())
}

/// Get reference to the global CryptoFS instance
pub fn get_cryptofs() -> Option<&'static CryptoFileSystem> {
    CRYPTOFS.get()
}

/// Helper to get CryptoFS or return error
#[inline]
fn require_cryptofs() -> CryptoResult<&'static CryptoFileSystem> {
    CRYPTOFS.get().ok_or(CryptoFsError::NotInitialized)
}

// ============================================================================
// KEY DERIVATION
// ============================================================================

/// Derive a 32-byte encryption key using HKDF-like construction with SHA-256
/// Key = SHA256(salt || path || context)
fn derive_key(path: &str, salt: &[u8; SALT_SIZE]) -> [u8; KEY_SIZE] {
    let path_bytes = path.as_bytes();
    let total_len = SALT_SIZE + path_bytes.len() + KEY_DERIVATION_CONTEXT.len();

    let mut input = Vec::with_capacity(total_len);
    input.extend_from_slice(salt);
    input.extend_from_slice(path_bytes);
    input.extend_from_slice(KEY_DERIVATION_CONTEXT);

    sha256(&input)
}

/// Generate a unique nonce for ChaCha20-Poly1305
/// Uses counter mode with random component for uniqueness
fn generate_nonce(counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    // First 4 bytes: random (adds entropy against related-key attacks)
    fill_random_bytes(&mut nonce[0..4]);
    // Last 8 bytes: counter (ensures uniqueness even with RNG issues)
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    nonce
}

// ============================================================================
// ENCRYPTION/DECRYPTION
// ============================================================================

/// Encrypt data using ChaCha20-Poly1305 AEAD
/// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
fn encrypt_data(data: &[u8], key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE]) -> CryptoResult<Vec<u8>> {
    // Encrypt with authenticated data
    let ct_and_tag = aead_encrypt(key, nonce, FILE_AAD, data)
        .map_err(|_| CryptoFsError::EncryptionFailed)?;

    // Prepend nonce to output
    let mut result = Vec::with_capacity(NONCE_SIZE + ct_and_tag.len());
    result.extend_from_slice(nonce);
    result.extend_from_slice(&ct_and_tag);
    Ok(result)
}

/// Decrypt data using ChaCha20-Poly1305 AEAD
/// Input: nonce (12 bytes) || ciphertext || tag (16 bytes)
fn decrypt_data(encrypted: &[u8], key: &[u8; KEY_SIZE]) -> CryptoResult<Vec<u8>> {
    if encrypted.len() < NONCE_SIZE + TAG_SIZE {
        return Err(CryptoFsError::DataTooShort);
    }

    // Extract nonce
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&encrypted[0..NONCE_SIZE]);

    // Get ciphertext and tag
    let ct_and_tag = &encrypted[NONCE_SIZE..];

    // Decrypt and verify tag
    aead_decrypt(key, &nonce, FILE_AAD, ct_and_tag)
        .map_err(|_| CryptoFsError::AuthenticationFailed)
}

// ============================================================================
// PATH VALIDATION
// ============================================================================

/// Validate a file path
fn validate_path(path: &str) -> CryptoResult<()> {
    if path.is_empty() {
        return Err(CryptoFsError::InvalidPath);
    }
    if path.len() > MAX_PATH_LEN {
        return Err(CryptoFsError::PathTooLong);
    }
    // Check for null bytes or other invalid characters
    if path.bytes().any(|b| b == 0) {
        return Err(CryptoFsError::InvalidPath);
    }
    Ok(())
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Create a new encrypted file (empty)
pub fn create_encrypted_file(_parent_inode: u64, path: &str, _caps: &[u8]) -> CryptoResult<u64> {
    validate_path(path)?;
    let fs = require_cryptofs()?;

    let mut inner = fs.inner.write();

    // Return existing inode if file exists
    if let Some(entry) = inner.files.get(path) {
        return Ok(entry.inode);
    }

    let inode = inner.next_inode.fetch_add(1, Ordering::Relaxed);
    let entry = FileEntry::new(inode, path)?;

    inner.files.insert(path.to_string(), entry);

    // Update stats
    drop(inner);
    let mut stats = fs.stats.write();
    stats.files += 1;

    Ok(inode)
}

/// Create an ephemeral file with initial data
pub fn create_ephemeral_file(path: &str, data: &[u8]) -> CryptoResult<u64> {
    validate_path(path)?;

    if data.len() > MAX_ENCRYPTED_FILE_SIZE {
        return Err(CryptoFsError::FileTooLarge);
    }

    let fs = require_cryptofs()?;
    let nonce = fs.next_nonce()?;

    let mut inner = fs.inner.write();

    let inode = inner.next_inode.fetch_add(1, Ordering::Relaxed);
    let mut entry = FileEntry::new(inode, path)?;

    // Encrypt initial data
    entry.encrypted = encrypt_data(data, &entry.key, &nonce)?;

    inner.files.insert(path.to_string(), entry);

    // Update stats
    drop(inner);
    let mut stats = fs.stats.write();
    stats.files += 1;
    stats.bytes_stored += data.len() as u64;
    stats.encryptions += 1;

    Ok(inode)
}

/// Read and decrypt file contents
pub fn read_encrypted(path: &str) -> CryptoResult<Vec<u8>> {
    validate_path(path)?;
    let fs = require_cryptofs()?;

    let inner = fs.inner.read();
    let entry = inner.files.get(path).ok_or(CryptoFsError::NotFound)?;

    // Empty file
    if entry.encrypted.is_empty() {
        return Ok(Vec::new());
    }

    // Clone key for decryption (to release lock during crypto)
    let key = entry.key;
    let encrypted = entry.encrypted.clone();
    drop(inner);

    // Decrypt
    let result = decrypt_data(&encrypted, &key);

    // Update stats
    let mut stats = fs.stats.write();
    if result.is_ok() {
        stats.decryptions += 1;
    } else {
        stats.decryption_failures += 1;
    }

    result
}

/// Write encrypted data (creates file if needed)
pub fn write_encrypted(path: &str, data: &[u8]) -> CryptoResult<()> {
    validate_path(path)?;

    if data.len() > MAX_ENCRYPTED_FILE_SIZE {
        return Err(CryptoFsError::FileTooLarge);
    }

    let fs = require_cryptofs()?;

    // Check if file exists
    {
        let inner = fs.inner.read();
        if !inner.files.contains_key(path) {
            drop(inner);
            create_ephemeral_file(path, data)?;
            return Ok(());
        }
    }

    // Generate new nonce for this write
    let nonce = fs.next_nonce()?;

    let mut inner = fs.inner.write();
    let entry = inner.files.get_mut(path).ok_or(CryptoFsError::NotFound)?;

    // Securely zeroize old encrypted data
    secure_zeroize(&mut entry.encrypted);

    // Encrypt new data
    entry.encrypted = encrypt_data(data, &entry.key, &nonce)?;
    entry.modified_at = crate::sys::timer::ticks();

    // Update stats
    drop(inner);
    let mut stats = fs.stats.write();
    stats.bytes_stored += data.len() as u64;
    stats.encryptions += 1;

    Ok(())
}

/// Delete a file securely (zeroizes all sensitive data)
pub fn delete_encrypted(path: &str) -> CryptoResult<()> {
    validate_path(path)?;
    let fs = require_cryptofs()?;

    let mut inner = fs.inner.write();

    if let Some(mut entry) = inner.files.remove(path) {
        // FileEntry::drop will securely clear data
        entry.secure_clear();

        drop(inner);
        let mut stats = fs.stats.write();
        stats.files = stats.files.saturating_sub(1);
        stats.secure_deletes += 1;

        return Ok(());
    }

    Err(CryptoFsError::NotFound)
}

/// Clear all CryptoFS state for ZeroState privacy wipe
/// Securely zeroizes all encryption keys, salts, and encrypted data
pub fn clear_crypto_state() {
    let fs = match CRYPTOFS.get() {
        Some(fs) => fs,
        None => return, // Not initialized, nothing to clear
    };

    let mut inner = fs.inner.write();

    // Securely zeroize all file entries
    for (_, entry) in inner.files.iter_mut() {
        entry.secure_clear();
    }

    // Clear the file map
    inner.files.clear();

    // Reset nonce counter (safe after key material is destroyed)
    inner.nonce_counter.store(0, Ordering::SeqCst);

    // Clear statistics
    drop(inner);
    let mut stats = fs.stats.write();
    *stats = CryptoFsStatistics::default();

    // Memory fence to ensure all writes complete
    compiler_fence(Ordering::SeqCst);
}

/// Rotate the key for a specific file
/// Creates new salt and re-encrypts with new key
pub fn rotate_file_key(path: &str) -> CryptoResult<()> {
    validate_path(path)?;
    let fs = require_cryptofs()?;

    // Read current plaintext
    let plaintext = read_encrypted(path)?;

    // Generate new nonce
    let nonce = fs.next_nonce()?;

    let mut inner = fs.inner.write();
    let entry = inner.files.get_mut(path).ok_or(CryptoFsError::NotFound)?;

    // Generate new salt and derive new key
    let mut new_salt = [0u8; SALT_SIZE];
    fill_random_bytes(&mut new_salt);
    let new_key = derive_key(path, &new_salt);

    // Securely zeroize old key material
    secure_zeroize_array(&mut entry.key);
    secure_zeroize_array(&mut entry.salt);
    secure_zeroize(&mut entry.encrypted);

    // Install new key material
    entry.salt = new_salt;
    entry.key = new_key;

    // Re-encrypt with new key
    entry.encrypted = encrypt_data(&plaintext, &entry.key, &nonce)?;
    entry.modified_at = crate::sys::timer::ticks();

    // Update stats
    drop(inner);
    let mut stats = fs.stats.write();
    stats.encryptions += 1;

    Ok(())
}

/// Check if nonce counter is approaching exhaustion
pub fn nonce_counter_warning() -> bool {
    if let Some(fs) = CRYPTOFS.get() {
        let inner = fs.inner.read();
        let counter = inner.nonce_counter.load(Ordering::Relaxed);
        // Warn if we've used more than 2^62 nonces (approaching 2^64 limit)
        counter > (1u64 << 62)
    } else {
        false
    }
}

// ============================================================================
// LEGACY API (for backward compatibility)
// ============================================================================

/// Create encrypted file (legacy interface)
pub fn create_encrypted_file_legacy(parent_inode: u64, path: &str, caps: &[u8]) -> Result<u64, &'static str> {
    create_encrypted_file(parent_inode, path, caps).map_err(|e| e.as_str())
}

/// Create ephemeral file (legacy interface)
pub fn create_ephemeral_file_legacy(path: &str, data: &[u8]) -> Result<u64, &'static str> {
    create_ephemeral_file(path, data).map_err(|e| e.as_str())
}

/// Read encrypted (legacy interface)
pub fn read_encrypted_legacy(path: &str) -> Result<Vec<u8>, &'static str> {
    read_encrypted(path).map_err(|e| e.as_str())
}

/// Write encrypted (legacy interface)
pub fn write_encrypted_legacy(path: &str, data: &[u8]) -> Result<(), &'static str> {
    write_encrypted(path, data).map_err(|e| e.as_str())
}

/// Delete encrypted (legacy interface)
pub fn delete_encrypted_legacy(path: &str) -> Result<(), &'static str> {
    delete_encrypted(path).map_err(|e| e.as_str())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_error_to_errno() {
        assert_eq!(CryptoFsError::NotFound.to_errno(), -2);
        assert_eq!(CryptoFsError::AlreadyExists.to_errno(), -17);
        assert_eq!(CryptoFsError::PathTooLong.to_errno(), -36);
    }

    #[test]
    fn test_validate_path() {
        assert!(validate_path("/test/file").is_ok());
        assert!(validate_path("").is_err());
        assert!(validate_path(&"x".repeat(MAX_PATH_LEN + 1)).is_err());
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = generate_nonce(0);
        let nonce2 = generate_nonce(1);
        // Counter portion should differ
        assert_ne!(nonce1[4..12], nonce2[4..12]);
    }

    #[test]
    fn test_secure_zeroize() {
        let mut data = [0xFFu8; 32];
        secure_zeroize(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }
}
