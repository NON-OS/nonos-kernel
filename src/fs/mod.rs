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

//! NØNOS Filesystem Subsystem
//! eK says - "Do you RAM ?"
//! RAM-only filesystem with encrypted storage support (ZeroState default).

#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::sync::atomic::{Ordering, compiler_fence};
use spin::{Once, RwLock};

use crate::memory::page_info::PageFlags;

// ============================================================================
// SUBMODULES
// ============================================================================

pub mod nonos_vfs;
pub mod nonos_crypto;
pub mod nonos_filesystem;
pub mod fd;
pub mod path;
pub mod cache;

/// Legacy VFS shim for compatibility
pub mod vfs {
    pub fn read_at_offset(_file_id: &str, _offset: usize, _buffer: &mut [u8]) -> Result<usize, &'static str> {
        Ok(0)
    }
}

// ============================================================================
// MODULE ALIASES
// ============================================================================

pub use nonos_vfs as nvfs;
pub use nonos_crypto as cryptofs;

// ============================================================================
// RE-EXPORTS
// ============================================================================

// VFS types
pub use nonos_vfs::{
    CowPageRef, DeviceOperations, FileBuffer, FileCacheEntry, FileMetadata, FileMode,
    FileSystemOperations, FileSystemType, FileType, IoOperation, IoRequest, IoStatistics,
    MountPoint, VfsInode, VirtualFileSystem, VfsError, VfsResult,
    get_vfs, get_vfs_mut, init_vfs,
};

// CryptoFS types
pub use nonos_crypto::{
    CryptoFileSystem, CryptoFsStatistics, CryptoFsError, CryptoResult,
    create_encrypted_file, create_ephemeral_file, get_cryptofs, init_cryptofs,
    read_encrypted, write_encrypted, delete_encrypted, clear_crypto_state,
    rotate_file_key, nonce_counter_warning,
};

// File descriptor operations
pub use fd::{
    open_file_syscall, read_file_descriptor, write_file_descriptor, close_file_descriptor,
    stat_file_syscall, fstat_file_syscall, rmdir_syscall, unlink_syscall, sync_all,
    FdError, FdResult,
};

// Path utilities
pub use path::{
    PathError, PathResult, cstr_to_string, normalize_path, validate_path,
    validate_path_secure, is_absolute, is_relative, parent, file_name, extension,
    join, join_normalize, join_secure, components, MAX_PATH_LEN,
};

// Filesystem types
pub use nonos_filesystem::{FsError, FsResult};

// Cache operations
pub use cache::{
    get_cache_statistics, get_cache_hit_ratio, init_all_caches, clear_all_caches,
    CACHE_STATS,
};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Maximum operations per sync batch
const MAX_OPERATIONS_PER_BATCH: usize = 64;

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Filesystem subsystem errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsSubsystemError {
    VfsNotInitialized,
    CryptoFsNotInitialized,
    ManagerNotInitialized,
    PageCacheError,
    InodeCacheError,
    DentryCacheError,
    WritebackError,
    StorageDeviceError,
    FilesystemFull,
    SuperblockCorrupted,
    InodeTableCorrupted,
    InternalError(&'static str),
}

impl FsSubsystemError {
    pub const fn to_errno(self) -> i32 {
        match self {
            Self::VfsNotInitialized | Self::CryptoFsNotInitialized |
            Self::ManagerNotInitialized | Self::WritebackError |
            Self::StorageDeviceError | Self::SuperblockCorrupted |
            Self::InodeTableCorrupted | Self::InternalError(_) => -5, // EIO
            Self::PageCacheError | Self::InodeCacheError |
            Self::DentryCacheError => -12,                             // ENOMEM
            Self::FilesystemFull => -28,                               // ENOSPC
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VfsNotInitialized => "VFS not initialized",
            Self::CryptoFsNotInitialized => "CryptoFS not initialized",
            Self::ManagerNotInitialized => "Filesystem manager not initialized",
            Self::PageCacheError => "Page cache error",
            Self::InodeCacheError => "Inode cache error",
            Self::DentryCacheError => "Dentry cache error",
            Self::WritebackError => "Writeback error",
            Self::StorageDeviceError => "Storage device error",
            Self::FilesystemFull => "Filesystem full",
            Self::SuperblockCorrupted => "Superblock corrupted",
            Self::InodeTableCorrupted => "Inode table corrupted",
            Self::InternalError(msg) => msg,
        }
    }
}

impl From<FsSubsystemError> for &'static str {
    fn from(err: FsSubsystemError) -> Self {
        err.as_str()
    }
}

pub type FsSubsystemResult<T> = Result<T, FsSubsystemError>;

// ============================================================================
// FILESYSTEM MANAGER
// ============================================================================

static FILESYSTEM_MANAGER: Once<RwLock<FileSystemManager>> = Once::new();

/// Filesystem manager coordinating VFS, CryptoFS, and caches
pub struct FileSystemManager {
    initialized: bool,
    vfs_initialized: bool,
    cryptofs_initialized: bool,
    stats: FileSystemManagerStats,
}

#[derive(Debug, Default, Clone)]
pub struct FileSystemManagerStats {
    pub syncs: u64,
    pub distributed_bytes: u64,
    pub errors: u64,
}

impl FileSystemManager {
    const fn new() -> Self {
        Self {
            initialized: false,
            vfs_initialized: false,
            cryptofs_initialized: false,
            stats: FileSystemManagerStats { syncs: 0, distributed_bytes: 0, errors: 0 },
        }
    }

    pub fn init(&mut self) -> FsSubsystemResult<()> {
        nonos_vfs::init_vfs();
        self.vfs_initialized = nonos_vfs::get_vfs().is_some();

        match nonos_crypto::init_cryptofs(1024 * 1024, 4096) {
            Ok(()) => self.cryptofs_initialized = true,
            Err(_) => self.cryptofs_initialized = false,
        }

        if let Some(vfs) = nonos_vfs::get_vfs() {
            vfs.mount("/", nonos_vfs::FileSystemType::RamFs);
            vfs.mount("/secure", nonos_vfs::FileSystemType::CryptoFS);
        }

        let _ = nonos_filesystem::init_nonos_filesystem();
        cache::init_all_caches();
        self.initialized = true;
        Ok(())
    }

    pub fn store_distributed_data(&mut self, data: &[u8], path: &str) -> FsSubsystemResult<()> {
        if !self.cryptofs_initialized {
            return Err(FsSubsystemError::CryptoFsNotInitialized);
        }
        nonos_crypto::create_ephemeral_file(path, data)
            .map_err(|_| FsSubsystemError::WritebackError)?;
        self.stats.distributed_bytes += data.len() as u64;
        Ok(())
    }

    pub fn get_storage_stats(&self) -> (usize, usize) { (0, 0) }
    pub fn get_statistics(&self) -> FileSystemManagerStats { self.stats.clone() }
    pub fn is_initialized(&self) -> bool { self.initialized }
}

pub fn init_filesystem_manager() -> FsSubsystemResult<()> {
    FILESYSTEM_MANAGER.call_once(|| {
        let mut manager = FileSystemManager::new();
        if let Err(e) = manager.init() {
            crate::log::logger::log_err!("Failed to initialize filesystem manager: {}", e.as_str());
        }
        RwLock::new(manager)
    });
    Ok(())
}

pub fn get_filesystem_manager() -> Option<&'static RwLock<FileSystemManager>> {
    FILESYSTEM_MANAGER.get()
}

// ============================================================================
// MAPPING TYPES
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingProtection {
    Read,
    ReadWrite,
    Execute,
    ReadExecute,
}

#[derive(Debug, Clone)]
pub struct FileMapping {
    pub file_id: u64,
    pub file_offset: u64,
    pub virtual_addr: x86_64::VirtAddr,
    pub size: usize,
    pub permissions: PageFlags,
}

impl FileMapping {
    pub fn new(file_id: u64, file_offset: u64, virtual_addr: x86_64::VirtAddr,
               size: usize, permissions: PageFlags) -> Self {
        Self { file_id, file_offset, virtual_addr, size, permissions }
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

/// Initialize the filesystem subsystem
pub fn init() {
    nonos_vfs::init_vfs();
    let _ = nonos_crypto::init_cryptofs(1024 * 1024, 4096);
    let _ = nonos_filesystem::init_nonos_filesystem();
    cache::init_all_caches();
    crate::log::logger::log_info!("Filesystem subsystem initialized (RAM-only mode)");
}

// ============================================================================
// FILE OPERATIONS
// ============================================================================

/// Read a file via VFS routing (RAM-only)
pub fn read_file(file_path: &str) -> Result<Vec<u8>, &'static str> {
    nonos_vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .read_file(file_path)
}

/// Alias for read_file
pub fn read_file_bytes(file_path: &str) -> Result<Vec<u8>, &'static str> {
    read_file(file_path)
}

/// List hidden files in a directory
pub fn list_hidden_files(_dir_path: &str) -> Vec<String> { Vec::new() }

/// Scan for sensitive file patterns
pub fn scan_for_sensitive_files(_dir_path: &str) -> Vec<String> { Vec::new() }

// ============================================================================
// SYNC OPERATIONS
// ============================================================================

/// Run filesystem sync operations
pub fn run_filesystem_sync() {
    flush_dirty_pages();

    if let Some(vfs) = nonos_vfs::get_vfs() {
        vfs.sync_metadata();
    }

    if let Some(cryptofs) = nonos_crypto::get_cryptofs() {
        cryptofs.sync_all();
    }

    sync_all_mounted_filesystems();

    if let Some(manager) = get_filesystem_manager() {
        manager.write().stats.syncs += 1;
    }

    crate::log::logger::log_info!("Filesystem sync completed");
}

/// Process pending filesystem operations
pub fn process_pending_operations() {
    let mut processed = 0;

    if let Some(vfs) = nonos_vfs::get_vfs_mut() {
        processed += vfs.process_pending_operations(MAX_OPERATIONS_PER_BATCH);
    }

    if let Some(cryptofs) = nonos_crypto::get_cryptofs() {
        let remaining = MAX_OPERATIONS_PER_BATCH.saturating_sub(processed);
        if remaining > 0 {
            processed += cryptofs.process_pending_operations(remaining);
        }
    }

    let remaining = MAX_OPERATIONS_PER_BATCH.saturating_sub(processed);
    if remaining > 0 {
        processed += process_file_cache_writeback(remaining);
    }

    let remaining = MAX_OPERATIONS_PER_BATCH.saturating_sub(processed);
    if remaining > 0 {
        processed += process_dentry_cache_updates(remaining);
    }

    let remaining = MAX_OPERATIONS_PER_BATCH.saturating_sub(processed);
    if remaining > 0 {
        processed += cache::process_inode_cache_maintenance(remaining);
    }

    if processed > 0 {
        crate::log_debug!("Processed {} filesystem operations", processed);
    }
}

/// Clear all filesystem caches for ZeroState privacy wipe
pub fn clear_caches() {
    nonos_vfs::clear_vfs_caches();
    nonos_crypto::clear_crypto_state();
    cache::clear_all_caches();
    compiler_fence(Ordering::SeqCst);
    crate::log::logger::log_info!("Filesystem caches cleared (ZeroState wipe)");
}

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

fn flush_dirty_pages() {
    let dirty_pages = cache::get_dirty_pages();
    for (file_id, page_list) in dirty_pages {
        for page in page_list {
            if write_page_to_storage(file_id, page.offset, &page.data).is_ok() {
                cache::mark_page_clean(file_id, page.offset);
            }
        }
    }
}

fn write_page_to_storage(file_id: u64, offset: u64, data: &[u8]) -> Result<(), &'static str> {
    if nonos_vfs::get_vfs().is_some() {
        cache::CACHE_STATS.writebacks.fetch_add(1, Ordering::Relaxed);
        crate::log_debug!("Writeback: file={}, offset={}, size={}", file_id, offset, data.len());
    }
    Ok(())
}

fn process_file_cache_writeback(max_operations: usize) -> usize {
    let mut processed = 0;
    let writeback_files = cache::get_writeback_files();

    for file in writeback_files.into_iter().take(max_operations) {
        if writeback_file_data(&file).is_ok() {
            cache::mark_file_clean(&file);
        } else {
            cache::schedule_writeback_retry(&file);
        }
        processed += 1;
    }
    processed
}

fn writeback_file_data(file: &cache::FileInfo) -> Result<(), &'static str> {
    if nonos_vfs::get_vfs().is_some() {
        crate::log_debug!("Writeback complete: {}", file.path);
        Ok(())
    } else {
        Err("VFS not initialized")
    }
}

fn process_dentry_cache_updates(max_operations: usize) -> usize {
    let mut processed = 0;
    let pending_dentries = cache::get_pending_dentry_updates();

    for dentry in pending_dentries.into_iter().take(max_operations) {
        if cache::update_directory_entry(&dentry).is_ok() {
            cache::commit_dentry_update(&dentry);
        }
        processed += 1;
    }
    processed
}

fn get_mounted_filesystems() -> Vec<MountPoint> {
    nonos_vfs::get_vfs().map(|vfs| vfs.mounts()).unwrap_or_default()
}

fn sync_all_mounted_filesystems() {
    for mount in get_mounted_filesystems() {
        match mount.filesystem {
            nonos_vfs::FileSystemType::CryptoFS => {
                if let Some(cryptofs) = nonos_crypto::get_cryptofs() {
                    cryptofs.sync_all();
                }
            }
            nonos_vfs::FileSystemType::TmpFs | nonos_vfs::FileSystemType::RamFs => {
                // RAM-only, no sync needed
            }
            _ => {}
        }
    }
}
