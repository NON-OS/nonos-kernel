// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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

//! NØNOS RAM-based filesystem with optional ChaCha20-Poly1305 encryption.
//! This module provides a high-performance in-memory filesystem with:
//! a) Optional per-file encryption using ChaCha20-Poly1305 AEAD
//! b) Secure memory zeroization on delete
//! c) Thread-safe concurrent access via RwLock
//! d) Path normalization and validation

#![no_std]

extern crate alloc;

use alloc::{collections::BTreeMap, collections::BTreeSet, string::String, vec::Vec, string::ToString, format};
use spin::{RwLock, Once};
use core::sync::atomic::{AtomicU64, Ordering, compiler_fence};

// Use real ChaCha20-Poly1305 AEAD from crypto module
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

/// Key size for ChaCha20 (256 bits = 32 bytes)
pub const KEY_SIZE: usize = 32;

/// Salt size for key derivation (128 bits = 16 bytes)
pub const SALT_SIZE: usize = 16;

/// Maximum file size (256 MiB for RAM filesystem)
pub const MAX_FILE_SIZE: usize = 256 * 1024 * 1024;

/// Maximum path length
pub const MAX_PATH_LEN: usize = 4096;

/// Maximum number of files
pub const MAX_FILES: usize = 65536;

/// Key derivation domain separator
const KEY_DERIVATION_CONTEXT: &[u8] = b"NONOS_FS_KEY_V1";

/// AEAD associated data for file encryption
const FILE_AAD: &[u8] = b"NONOS_FS_FILE";

// ============================================================================
// STRUCTURED ERROR HANDLING
// ============================================================================

/// Filesystem operation errors with detailed messages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// Filesystem not initialized
    NotInitialized,
    /// File not found
    NotFound,
    /// File already exists
    AlreadyExists,
    /// Path too long
    PathTooLong,
    /// Invalid path (empty, null bytes, etc.)
    InvalidPath,
    /// File too large
    FileTooLarge,
    /// Too many files
    TooManyFiles,
    /// No encryption key found for file
    NoEncryptionKey,
    /// Encrypted data too short (corrupted)
    DataTooShort,
    /// Decryption failed (authentication error)
    DecryptionFailed,
    /// Encryption failed
    EncryptionFailed,
    /// Directory not found
    DirectoryNotFound,
    /// Not a directory
    NotADirectory,
    /// Directory not empty
    DirectoryNotEmpty,
    /// Permission denied
    PermissionDenied,
    /// I/O error
    IoError(&'static str),
}

impl FsError {
    /// Convert to errno-style negative integer
    pub const fn to_errno(self) -> i32 {
        match self {
            FsError::NotInitialized => -5,    // EIO
            FsError::NotFound => -2,          // ENOENT
            FsError::AlreadyExists => -17,    // EEXIST
            FsError::PathTooLong => -36,      // ENAMETOOLONG
            FsError::InvalidPath => -22,      // EINVAL
            FsError::FileTooLarge => -27,     // EFBIG
            FsError::TooManyFiles => -28,     // ENOSPC
            FsError::NoEncryptionKey => -5,   // EIO
            FsError::DataTooShort => -5,      // EIO
            FsError::DecryptionFailed => -5,  // EIO
            FsError::EncryptionFailed => -5,  // EIO
            FsError::DirectoryNotFound => -2, // ENOENT
            FsError::NotADirectory => -20,    // ENOTDIR
            FsError::DirectoryNotEmpty => -39, // ENOTEMPTY
            FsError::PermissionDenied => -13, // EACCES
            FsError::IoError(_) => -5,        // EIO
        }
    }

    /// Get human-readable error message
    pub const fn as_str(self) -> &'static str {
        match self {
            FsError::NotInitialized => "Filesystem not initialized",
            FsError::NotFound => "File not found",
            FsError::AlreadyExists => "File already exists",
            FsError::PathTooLong => "Path too long",
            FsError::InvalidPath => "Invalid path",
            FsError::FileTooLarge => "File too large",
            FsError::TooManyFiles => "Too many files",
            FsError::NoEncryptionKey => "No encryption key found",
            FsError::DataTooShort => "Encrypted data too short",
            FsError::DecryptionFailed => "Decryption failed",
            FsError::EncryptionFailed => "Encryption failed",
            FsError::DirectoryNotFound => "Directory not found",
            FsError::NotADirectory => "Not a directory",
            FsError::DirectoryNotEmpty => "Directory not empty",
            FsError::PermissionDenied => "Permission denied",
            FsError::IoError(msg) => msg,
        }
    }
}

impl From<FsError> for &'static str {
    fn from(err: FsError) -> Self {
        err.as_str()
    }
}

/// Result type for filesystem operations
pub type FsResult<T> = Result<T, FsError>;

// ============================================================================
// SECURE MEMORY OPERATIONS
// ============================================================================

/// Securely zeroize a byte slice, preventing compiler optimization
#[inline]
fn secure_zeroize(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Securely zeroize a fixed-size array
#[inline]
fn secure_zeroize_array<const N: usize>(data: &mut [u8; N]) {
    secure_zeroize(data.as_mut_slice());
}

// ============================================================================
// PATH HANDLING
// ============================================================================

/// Validate a file path
fn validate_path(path: &str) -> FsResult<()> {
    if path.is_empty() {
        return Err(FsError::InvalidPath);
    }
    if path.len() > MAX_PATH_LEN {
        return Err(FsError::PathTooLong);
    }
    // Check for null bytes
    if path.bytes().any(|b| b == 0) {
        return Err(FsError::InvalidPath);
    }
    // Check for path traversal attempts
    if path.contains("..") {
        return Err(FsError::InvalidPath);
    }
    Ok(())
}

/// Normalize a file path by removing redundant components
pub fn normalize_path(path: &str) -> String {
    let mut components: Vec<&str> = Vec::new();

    for component in path.split('/') {
        match component {
            "" | "." => continue,
            ".." => {
                components.pop();
            }
            c => components.push(c),
        }
    }

    let mut result = String::with_capacity(path.len());
    if path.starts_with('/') {
        result.push('/');
    }

    for (i, component) in components.iter().enumerate() {
        if i > 0 {
            result.push('/');
        }
        result.push_str(component);
    }

    if result.is_empty() {
        result.push('/');
    }

    result
}

// ============================================================================
// FILESYSTEM TYPES
// ============================================================================

/// Filesystem type/mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonosFileSystemType {
    /// Quantum-safe encryption (future)
    QuantumSafe = 0,
    /// Standard ChaCha20-Poly1305 encryption
    Encrypted = 1,
    /// No encryption (ephemeral RAM only)
    Ephemeral = 2,
}

// ============================================================================
// FILE KEY STRUCTURE
// ============================================================================

/// File encryption key with salt for secure key derivation
#[derive(Debug)]
struct FileKey {
    key: [u8; KEY_SIZE],
    salt: [u8; SALT_SIZE],
}

impl FileKey {
    /// Create a new file key with random salt
    fn new(filename: &str) -> Self {
        let mut salt = [0u8; SALT_SIZE];
        fill_random_bytes(&mut salt);
        let key = derive_key(filename, &salt);
        Self { key, salt }
    }

    /// Securely clear key material
    fn secure_clear(&mut self) {
        secure_zeroize_array(&mut self.key);
        secure_zeroize_array(&mut self.salt);
    }
}

impl Drop for FileKey {
    fn drop(&mut self) {
        self.secure_clear();
    }
}

// ============================================================================
// FILE STRUCTURE
// ============================================================================

/// A file in the NØNOS filesystem
#[derive(Debug)]
pub struct NonosFile {
    /// File name/path
    pub name: String,
    /// Encrypted data: nonce (12 bytes) || ciphertext || tag (16 bytes)
    /// Or plaintext if encryption is disabled
    pub data: Vec<u8>,
    /// Original plaintext size
    pub size: usize,
    /// Creation timestamp (ticks)
    pub created: u64,
    /// Last modification timestamp (ticks)
    pub modified: u64,
    /// Whether file is encrypted
    pub encrypted: bool,
    /// Whether file has quantum-safe protection
    pub quantum_protected: bool,
}

impl NonosFile {
    /// Securely clear file data
    fn secure_clear(&mut self) {
        secure_zeroize(&mut self.data);
        self.data.clear();
        self.size = 0;
    }
}

impl Drop for NonosFile {
    fn drop(&mut self) {
        self.secure_clear();
    }
}

// ============================================================================
// FILE INFO (public metadata)
// ============================================================================

/// Public file metadata
#[derive(Debug, Clone)]
pub struct NonosFileInfo {
    pub name: String,
    pub size: usize,
    pub created: u64,
    pub modified: u64,
    pub encrypted: bool,
    pub quantum_protected: bool,
}

// ============================================================================
// STATISTICS
// ============================================================================

/// Filesystem statistics
#[derive(Debug, Default, Clone)]
pub struct FsStatistics {
    /// Number of files
    pub files: u64,
    /// Total bytes stored (plaintext)
    pub bytes_stored: u64,
    /// Number of read operations
    pub reads: u64,
    /// Number of write operations
    pub writes: u64,
    /// Number of delete operations
    pub deletes: u64,
    /// Number of encryption operations
    pub encryptions: u64,
    /// Number of decryption operations
    pub decryptions: u64,
    /// Number of failed decryptions
    pub decryption_failures: u64,
}

// ============================================================================
// KEY DERIVATION
// ============================================================================

/// Derive a 32-byte encryption key using HKDF-like construction with SHA-256
fn derive_key(filename: &str, salt: &[u8; SALT_SIZE]) -> [u8; KEY_SIZE] {
    let filename_bytes = filename.as_bytes();
    let total_len = SALT_SIZE + filename_bytes.len() + KEY_DERIVATION_CONTEXT.len();

    let mut input = Vec::with_capacity(total_len);
    input.extend_from_slice(salt);
    input.extend_from_slice(filename_bytes);
    input.extend_from_slice(KEY_DERIVATION_CONTEXT);

    sha256(&input)
}

// ============================================================================
// FILESYSTEM IMPLEMENTATION
// ============================================================================

/// NØNOS RAM-based filesystem
#[derive(Debug)]
pub struct NonosFilesystem {
    /// Filesystem type/mode
    filesystem_type: NonosFileSystemType,
    /// File storage (path -> file)
    files: RwLock<BTreeMap<String, NonosFile>>,
    /// Encryption keys (path -> key)
    file_keys: RwLock<BTreeMap<String, FileKey>>,
    /// Whether encryption is enabled
    encryption_enabled: bool,
    /// Global nonce counter for unique nonces
    nonce_counter: AtomicU64,
    /// Statistics
    stats: RwLock<FsStatistics>,
}

impl NonosFilesystem {
    /// Create a new filesystem (const for static initialization)
    pub const fn new() -> Self {
        Self {
            filesystem_type: NonosFileSystemType::Ephemeral,
            files: RwLock::new(BTreeMap::new()),
            file_keys: RwLock::new(BTreeMap::new()),
            encryption_enabled: false,
            nonce_counter: AtomicU64::new(0),
            stats: RwLock::new(FsStatistics {
                files: 0,
                bytes_stored: 0,
                reads: 0,
                writes: 0,
                deletes: 0,
                encryptions: 0,
                decryptions: 0,
                decryption_failures: 0,
            }),
        }
    }

    /// Create a new filesystem with encryption enabled
    pub fn new_encrypted() -> Self {
        Self {
            filesystem_type: NonosFileSystemType::Encrypted,
            files: RwLock::new(BTreeMap::new()),
            file_keys: RwLock::new(BTreeMap::new()),
            encryption_enabled: true,
            nonce_counter: AtomicU64::new(0),
            stats: RwLock::new(FsStatistics::default()),
        }
    }

    /// Enable encryption (for late initialization)
    pub fn enable_encryption(&mut self) {
        self.encryption_enabled = true;
        self.filesystem_type = NonosFileSystemType::Encrypted;
    }

    /// Get current timestamp
    fn get_timestamp(&self) -> u64 {
        crate::time::current_ticks()
    }

    /// Generate a unique nonce for ChaCha20-Poly1305
    fn generate_nonce(&self) -> [u8; NONCE_SIZE] {
        let counter = self.nonce_counter.fetch_add(1, Ordering::SeqCst);
        let mut nonce = [0u8; NONCE_SIZE];
        // First 4 bytes: random
        fill_random_bytes(&mut nonce[0..4]);
        // Last 8 bytes: counter (ensures uniqueness)
        nonce[4..NONCE_SIZE].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    /// Ensure encryption key exists for file
    fn ensure_key(&self, filename: &str) -> FsResult<[u8; KEY_SIZE]> {
        // Try read lock first
        {
            let keys = self.file_keys.read();
            if let Some(file_key) = keys.get(filename) {
                return Ok(file_key.key);
            }
        }

        // Need write lock to create key
        let mut keys = self.file_keys.write();

        // Double-check after acquiring write lock
        if let Some(file_key) = keys.get(filename) {
            return Ok(file_key.key);
        }

        let file_key = FileKey::new(filename);
        let key = file_key.key;
        keys.insert(filename.to_string(), file_key);
        Ok(key)
    }

    /// Get existing key for file (for decryption)
    fn get_key(&self, filename: &str) -> FsResult<[u8; KEY_SIZE]> {
        let keys = self.file_keys.read();
        let file_key = keys.get(filename).ok_or(FsError::NoEncryptionKey)?;
        Ok(file_key.key)
    }

    /// Encrypt data using ChaCha20-Poly1305 AEAD
    fn encrypt_file_data(&self, data: &[u8], key: &[u8; KEY_SIZE]) -> FsResult<Vec<u8>> {
        let nonce = self.generate_nonce();

        let ct_and_tag = aead_encrypt(key, &nonce, FILE_AAD, data)
            .map_err(|_| FsError::EncryptionFailed)?;

        let mut result = Vec::with_capacity(NONCE_SIZE + ct_and_tag.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ct_and_tag);

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.encryptions += 1;
        }

        Ok(result)
    }

    /// Decrypt data using ChaCha20-Poly1305 AEAD
    fn decrypt_file_data(&self, encrypted: &[u8], key: &[u8; KEY_SIZE]) -> FsResult<Vec<u8>> {
        if encrypted.len() < NONCE_SIZE + TAG_SIZE {
            return Err(FsError::DataTooShort);
        }

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&encrypted[0..NONCE_SIZE]);

        let ct_and_tag = &encrypted[NONCE_SIZE..];

        let result = aead_decrypt(key, &nonce, FILE_AAD, ct_and_tag);

        // Update stats
        {
            let mut stats = self.stats.write();
            if result.is_ok() {
                stats.decryptions += 1;
            } else {
                stats.decryption_failures += 1;
            }
        }

        result.map_err(|_| FsError::DecryptionFailed)
    }

    // ========================================================================
    // PUBLIC API
    // ========================================================================

    /// Create a new file
    pub fn create_file(&self, name: &str, data: &[u8]) -> FsResult<()> {
        validate_path(name)?;

        if data.len() > MAX_FILE_SIZE {
            return Err(FsError::FileTooLarge);
        }

        // Check file limit
        {
            let files = self.files.read();
            if files.len() >= MAX_FILES {
                return Err(FsError::TooManyFiles);
            }
        }

        let timestamp = self.get_timestamp();

        let stored = if self.encryption_enabled {
            let key = self.ensure_key(name)?;
            self.encrypt_file_data(data, &key)?
        } else {
            data.to_vec()
        };

        let file = NonosFile {
            name: name.to_string(),
            size: data.len(),
            data: stored,
            created: timestamp,
            modified: timestamp,
            encrypted: self.encryption_enabled,
            quantum_protected: matches!(self.filesystem_type, NonosFileSystemType::QuantumSafe),
        };

        self.files.write().insert(name.to_string(), file);

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.files += 1;
            stats.bytes_stored += data.len() as u64;
            stats.writes += 1;
        }

        Ok(())
    }

    /// Read a file's contents
    pub fn read_file(&self, name: &str) -> FsResult<Vec<u8>> {
        validate_path(name)?;

        let files = self.files.read();
        let file = files.get(name).ok_or(FsError::NotFound)?;

        let result = if file.encrypted {
            let key = self.get_key(name)?;
            self.decrypt_file_data(&file.data, &key)?
        } else {
            file.data.clone()
        };

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.reads += 1;
        }

        Ok(result)
    }

    /// Write to an existing file
    pub fn write_file(&self, name: &str, data: &[u8]) -> FsResult<()> {
        validate_path(name)?;

        if data.len() > MAX_FILE_SIZE {
            return Err(FsError::FileTooLarge);
        }

        let mut files = self.files.write();
        let file = files.get_mut(name).ok_or(FsError::NotFound)?;

        // Securely zeroize old data
        secure_zeroize(&mut file.data);

        let stored = if self.encryption_enabled {
            let key = self.get_key(name)?;
            self.encrypt_file_data(data, &key)?
        } else {
            data.to_vec()
        };

        file.data = stored;
        file.size = data.len();
        file.modified = self.get_timestamp();

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.bytes_stored += data.len() as u64;
            stats.writes += 1;
        }

        Ok(())
    }

    /// Delete a file securely
    pub fn delete_file(&self, name: &str) -> FsResult<()> {
        validate_path(name)?;

        // Zeroize and remove file
        {
            let mut files = self.files.write();
            if let Some(mut file) = files.remove(name) {
                file.secure_clear();
            } else {
                return Err(FsError::NotFound);
            }
        }

        // Zeroize and remove key
        {
            let mut keys = self.file_keys.write();
            if let Some(mut key) = keys.remove(name) {
                key.secure_clear();
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.files = stats.files.saturating_sub(1);
            stats.deletes += 1;
        }

        Ok(())
    }

    /// List all files
    pub fn list_files(&self) -> Vec<String> {
        self.files.read().keys().cloned().collect()
    }

    /// Get file metadata
    pub fn get_file_info(&self, name: &str) -> FsResult<NonosFileInfo> {
        validate_path(name)?;

        let files = self.files.read();
        let file = files.get(name).ok_or(FsError::NotFound)?;

        Ok(NonosFileInfo {
            name: file.name.clone(),
            size: file.size,
            created: file.created,
            modified: file.modified,
            encrypted: file.encrypted,
            quantum_protected: file.quantum_protected,
        })
    }

    /// Check if a file exists
    pub fn exists(&self, name: &str) -> bool {
        self.files.read().contains_key(name)
    }

    /// Get filesystem statistics
    pub fn stats(&self) -> FsStatistics {
        self.stats.read().clone()
    }

    /// Get number of files
    pub fn file_count(&self) -> usize {
        self.files.read().len()
    }

    /// Get total storage used
    pub fn storage_used(&self) -> usize {
        self.files.read().values().map(|f| f.data.len()).sum()
    }

    /// Clear all files securely
    pub fn clear_all(&self) {
        // Zeroize all files
        {
            let mut files = self.files.write();
            for (_, file) in files.iter_mut() {
                secure_zeroize(&mut file.data);
            }
            files.clear();
        }

        // Zeroize all keys
        {
            let mut keys = self.file_keys.write();
            for (_, key) in keys.iter_mut() {
                key.secure_clear();
            }
            keys.clear();
        }

        // Reset stats
        {
            let mut stats = self.stats.write();
            *stats = FsStatistics::default();
        }

        // Reset nonce counter
        self.nonce_counter.store(0, Ordering::SeqCst);

        compiler_fence(Ordering::SeqCst);
    }

    /// List directory contents
    pub fn list_dir(&self, path: &str) -> FsResult<Vec<String>> {
        let path_components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let files = self.files.read();

        let mut entries = Vec::new();
        let mut dirs: BTreeSet<String> = BTreeSet::new();

        for (filename, _) in files.iter() {
            let file_components: Vec<&str> = filename.split('/').filter(|s| !s.is_empty()).collect();

            // Check if file is directly in requested directory
            if file_components.len() == path_components.len() + 1 {
                let mut matches = true;
                for (i, component) in path_components.iter().enumerate() {
                    if i >= file_components.len() || file_components[i] != *component {
                        matches = false;
                        break;
                    }
                }
                if matches {
                    if let Some(last) = file_components.last() {
                        entries.push((*last).to_string());
                    }
                }
            }

            // Check for subdirectories
            if file_components.len() > path_components.len() + 1 {
                let mut matches = true;
                for (i, component) in path_components.iter().enumerate() {
                    if i >= file_components.len() || file_components[i] != *component {
                        matches = false;
                        break;
                    }
                }
                if matches && path_components.len() < file_components.len() {
                    dirs.insert(file_components[path_components.len()].to_string());
                }
            }
        }

        // Add directories with "/" suffix
        for dir in dirs {
            entries.push(format!("{}/", dir));
        }

        Ok(entries)
    }
}

// ============================================================================
// GLOBAL INSTANCE
// ============================================================================

/// Global filesystem instance (static for const initialization)
pub static NONOS_FILESYSTEM: NonosFilesystem = NonosFilesystem::new();

/// Once-initialized global filesystem
static GLOBAL_FS: Once<NonosFilesystem> = Once::new();

/// Initialize the global filesystem
pub fn init_nonos_filesystem() -> FsResult<()> {
    GLOBAL_FS.call_once(|| NonosFilesystem::new());
    Ok(())
}

/// Get reference to global filesystem
pub fn get_filesystem() -> Option<&'static NonosFilesystem> {
    GLOBAL_FS.get()
}

// ============================================================================
// PUBLIC API (module-level functions)
// ============================================================================

/// Create a file
pub fn create_file(name: &str, data: &[u8]) -> FsResult<()> {
    NONOS_FILESYSTEM.create_file(name, data)
}

/// Read a file
pub fn read_file(name: &str) -> FsResult<Vec<u8>> {
    NONOS_FILESYSTEM.read_file(name)
}

/// Write to a file
pub fn write_file(name: &str, data: &[u8]) -> FsResult<()> {
    NONOS_FILESYSTEM.write_file(name, data)
}

/// Delete a file
pub fn delete_file(name: &str) -> FsResult<()> {
    NONOS_FILESYSTEM.delete_file(name)
}

/// List all files
pub fn list_files() -> Vec<String> {
    NONOS_FILESYSTEM.list_files()
}

/// Check if file exists
pub fn exists(name: &str) -> bool {
    NONOS_FILESYSTEM.exists(name)
}

/// Check if file exists (alias)
pub fn file_exists(name: &str) -> bool {
    exists(name)
}

/// List directory contents
pub fn list_dir(path: &str) -> FsResult<Vec<String>> {
    if let Some(fs) = GLOBAL_FS.get() {
        fs.list_dir(path)
    } else {
        NONOS_FILESYSTEM.list_dir(path)
    }
}

/// Get filesystem statistics
pub fn stats() -> FsStatistics {
    NONOS_FILESYSTEM.stats()
}

/// Initialize filesystem with marker file
pub fn init_nonos_fs() -> FsResult<()> {
    crate::log_info!("Initializing NØNOS RAM-only filesystem");

    match create_file("zero_state_init", b"ZeroState FS initialized (RAM-only)") {
        Ok(_) => {
            crate::log_info!("NØNOS filesystem initialization successful");
            Ok(())
        }
        Err(e) => {
            crate::log_err!("NØNOS filesystem initialization failed: {}", e.as_str());
            Err(FsError::IoError("Failed to initialize filesystem"))
        }
    }
}

// ============================================================================
// LEGACY API (backward compatibility)
// ============================================================================

/// Create file (legacy interface)
pub fn create_file_legacy(name: &str, data: &[u8]) -> Result<(), &'static str> {
    create_file(name, data).map_err(|e| e.as_str())
}

/// Read file (legacy interface)
pub fn read_file_legacy(name: &str) -> Result<Vec<u8>, &'static str> {
    read_file(name).map_err(|e| e.as_str())
}

/// Write file (legacy interface)
pub fn write_file_legacy(name: &str, data: &[u8]) -> Result<(), &'static str> {
    write_file(name, data).map_err(|e| e.as_str())
}

/// Delete file (legacy interface)
pub fn delete_file_legacy(name: &str) -> Result<(), &'static str> {
    delete_file(name).map_err(|e| e.as_str())
}

/// List dir (legacy interface)
pub fn list_dir_legacy(path: &str) -> Result<Vec<String>, &'static str> {
    list_dir(path).map_err(|e| e.as_str())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fs_error_to_errno() {
        assert_eq!(FsError::NotFound.to_errno(), -2);
        assert_eq!(FsError::AlreadyExists.to_errno(), -17);
        assert_eq!(FsError::PathTooLong.to_errno(), -36);
    }

    #[test]
    fn test_validate_path() {
        assert!(validate_path("/test/file").is_ok());
        assert!(validate_path("").is_err());
        assert!(validate_path("../etc/passwd").is_err());
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("/a/b/c"), "/a/b/c");
        assert_eq!(normalize_path("/a//b/./c"), "/a/b/c");
        assert_eq!(normalize_path("/a/b/../c"), "/a/c");
        assert_eq!(normalize_path("a/b/c"), "a/b/c");
    }

    #[test]
    fn test_secure_zeroize() {
        let mut data = [0xFFu8; 32];
        secure_zeroize(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }
}
