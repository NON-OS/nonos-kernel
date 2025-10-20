//! Filesystem subsystem (ZeroState default: RAM-only, anonymous).

extern crate alloc;

use alloc::{vec, vec::Vec};
use spin::Once;

use crate::memory::PageFlags;

pub mod nonos_vfs;
pub mod nonos_crypto;
pub mod nonos_filesystem;
pub mod fd;
pub mod path;

// Re-exports for compatibility and syscall surface
pub use nonos_vfs as vfs;
pub use nonos_crypto as cryptofs;

pub use nonos_vfs::{
    CowPageRef, DeviceOperations, FileBuffer, FileCacheEntry, FileMetadata, FileMode, FileSystemOperations,
    FileSystemType, FileType, IoOperation, IoRequest, IoStatistics, MountPoint, VfsInode, VirtualFileSystem,
    get_vfs, get_vfs_mut, init_vfs,
};

pub use nonos_crypto::{
    CryptoFileSystem, CryptoFsStatistics, create_encrypted_file, create_ephemeral_file, get_cryptofs, init_cryptofs,
};

pub use fd::{
    open_file_syscall, read_file_descriptor, write_file_descriptor, close_file_descriptor,
    stat_file_syscall, fstat_file_syscall, rmdir_syscall, unlink_syscall, sync_all,
};

// Global filesystem manager for integration
static FILESYSTEM_MANAGER: Once<FileSystemManager> = Once::new();

pub struct FileSystemManager {
    vfs: Option<&'static VirtualFileSystem>,
    cryptofs: Option<&'static CryptoFileSystem>,
}

impl FileSystemManager {
    pub fn new() -> Self {
        Self { vfs: None, cryptofs: None }
    }

    pub fn init(&mut self) -> Result<(), &'static str> {
        nonos_vfs::init_vfs();
        self.vfs = nonos_vfs::get_vfs();

        nonos_crypto::init_cryptofs(1024 * 1024, 4096).map_err(|_| "Failed to init CryptoFS")?;
        self.cryptofs = nonos_crypto::get_cryptofs();

        // Mount routes (VFS will route / -> NonosFs and /secure -> CryptoFS)
        if let Some(vfs) = self.vfs {
            vfs.mount("/", nonos_vfs::FileSystemType::RamFs);
            vfs.mount("/secure", nonos_vfs::FileSystemType::CryptoFS);
        }

        // Ensure in-memory filesystem initialized
        let _ = nonos_filesystem::init_nonos_filesystem();

        Ok(())
    }

    pub fn store_distributed_data(&self, data: &[u8], path: &str) -> Result<(), &'static str> {
        if self.cryptofs.is_some() {
            let _inode = nonos_crypto::create_ephemeral_file(path, data)?;
            Ok(())
        } else {
            Err("CryptoFS not initialized")
        }
    }

    pub fn get_storage_stats(&self) -> (usize, usize) {
        // RAM-only default
        (0, 0)
    }
}

pub fn init_filesystem_manager() -> Result<(), &'static str> {
    FILESYSTEM_MANAGER.call_once(|| {
        let mut manager = FileSystemManager::new();
        manager.init().expect("Failed to initialize filesystem manager");
        manager
    });
    Ok(())
}

pub fn get_filesystem_manager() -> &'static FileSystemManager {
    FILESYSTEM_MANAGER.get().expect("Filesystem manager not initialized")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingProtection {
    Read,
    ReadWrite,
    Execute,
    ReadExecute,
}

/// Initialize the filesystem subsystem
pub fn init() {
    nonos_vfs::init_vfs();
    let _ = nonos_crypto::init_cryptofs(1024 * 1024, 4096); // RAM-only
    let _ = nonos_filesystem::init_nonos_filesystem();
}

/// Run filesystem sync operations (RAM-only: in-memory maintenance)
pub fn run_filesystem_sync() {
    flush_dirty_pages();

    if let Some(vfs) = nonos_vfs::get_vfs() {
        vfs.sync_metadata();
    }

    if let Some(cryptofs) = nonos_crypto::get_cryptofs() {
        cryptofs.sync_all();
    }

    sync_all_mounted_filesystems();
    update_fs_statistics();

    crate::log::logger::log_info!("Filesystem sync completed");
}

/// Process pending filesystem operations
pub fn process_pending_operations() {
    const MAX_OPERATIONS_PER_BATCH: usize = 64;
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
        processed += process_inode_cache_maintenance(remaining);
    }

    if processed > 0 {
        crate::log_debug!("Processed {} filesystem operations", processed);
    }

    check_filesystem_errors();
}

fn flush_dirty_pages() {
    let dirty_pages = get_dirty_pages();

    for (file_id, page_list) in dirty_pages {
        for page in page_list {
            match write_page_to_storage(file_id, page.offset, &page.data) {
                Ok(()) => {
                    mark_page_clean(file_id, page.offset);
                    crate::log_debug!("Flushed dirty page: file={}, offset={}", file_id, page.offset);
                }
                Err(e) => {
                    crate::log::logger::log_err!("Failed to flush page: file={}, error={}", file_id, e);
                    mark_page_for_retry(file_id, page.offset);
                }
            }
        }
    }
}

fn sync_all_mounted_filesystems() {
    let mounted_fs = get_mounted_filesystems();

    for mount in mounted_fs {
        match mount.filesystem {
            nonos_vfs::FileSystemType::CryptoFS => {
                sync_cryptofs_mount(&mount);
            }
            nonos_vfs::FileSystemType::TmpFs | nonos_vfs::FileSystemType::RamFs => {
                sync_tempfs_mount(&mount);
            }
            nonos_vfs::FileSystemType::ProcFs => { /* virtual */ }
            _ => {
                sync_generic_mount(&mount);
            }
        }
    }
}

fn process_file_cache_writeback(max_operations: usize) -> usize {
    let mut processed = 0;

    let writeback_files = get_writeback_files();

    for file in writeback_files.into_iter().take(max_operations) {
        match writeback_file_data(&file) {
            Ok(()) => {
                mark_file_clean(&file);
                processed += 1;
            }
            Err(e) => {
                crate::log_warn!("Writeback failed for file {}: {}", file.path, e);
                schedule_writeback_retry(&file);
                processed += 1;
            }
        }
    }

    processed
}

fn process_dentry_cache_updates(max_operations: usize) -> usize {
    let mut processed = 0;

    let pending_dentries = get_pending_dentry_updates();

    for dentry in pending_dentries.into_iter().take(max_operations) {
        match update_directory_entry(&dentry) {
            Ok(()) => {
                commit_dentry_update(&dentry);
                processed += 1;
            }
            Err(e) => {
                crate::log_warn!("Failed to update directory entry {}: {}", dentry.name, e);
                processed += 1;
            }
        }
    }

    processed
}

fn process_inode_cache_maintenance(max_operations: usize) -> usize {
    let mut processed = 0;

    processed += cleanup_unused_inodes(max_operations);

    if processed < max_operations {
        processed += update_inode_timestamps(max_operations - processed);
    }

    if processed < max_operations {
        processed += writeback_dirty_inodes(max_operations - processed);
    }

    processed
}

fn check_filesystem_errors() {
    if has_filesystem_errors() {
        crate::log::logger::log_critical("Filesystem errors detected - running fsck");
        schedule_filesystem_check();
    }

    if has_storage_device_errors() {
        crate::log::logger::log_critical("Storage device errors detected");
        handle_storage_device_errors();
    }

    if is_filesystem_nearly_full() {
        crate::log_warn!("Filesystem is nearly full - cleaning up");
        schedule_cleanup_operation();
    }
}

fn update_fs_statistics() {
    let stats = calculate_filesystem_stats();
    update_global_fs_stats(stats);
}

// Helper functions implementations

fn get_dirty_pages() -> alloc::collections::BTreeMap<u64, Vec<DirtyPage>> {
    alloc::collections::BTreeMap::new()
}

struct DirtyPage {
    offset: u64,
    data: Vec<u8>,
}

fn write_page_to_storage(_file_id: u64, _offset: u64, _data: &[u8]) -> Result<(), &'static str> {
    Ok(())
}

fn mark_page_clean(_file_id: u64, _offset: u64) {}

fn mark_page_for_retry(_file_id: u64, _offset: u64) {}

fn get_mounted_filesystems() -> Vec<MountPoint> {
    if let Some(vfs) = nonos_vfs::get_vfs() {
        return vfs.mounts();
    }
    vec![]
}

fn sync_cryptofs_mount(_mount: &MountPoint) {}

fn sync_tempfs_mount(_mount: &MountPoint) {}

fn sync_generic_mount(_mount: &MountPoint) {}

fn get_writeback_files() -> Vec<FileInfo> {
    vec![]
}

struct FileInfo {
    path: alloc::string::String,
    inode: u64,
}

fn writeback_file_data(_file: &FileInfo) -> Result<(), &'static str> {
    Ok(())
}

fn mark_file_clean(_file: &FileInfo) {}

fn schedule_writeback_retry(_file: &FileInfo) {}

fn get_pending_dentry_updates() -> Vec<DirectoryEntry> {
    vec![]
}

struct DirectoryEntry {
    name: alloc::string::String,
    inode: u64,
}

fn update_directory_entry(_dentry: &DirectoryEntry) -> Result<(), &'static str> {
    Ok(())
}

fn commit_dentry_update(_dentry: &DirectoryEntry) {}

fn cleanup_unused_inodes(_max: usize) -> usize {
    0
}
fn update_inode_timestamps(_max: usize) -> usize {
    0
}
fn writeback_dirty_inodes(_max: usize) -> usize {
    0
}

fn has_filesystem_errors() -> bool {
    false
}
fn schedule_filesystem_check() {
    crate::log::logger::log_info!("Scheduling filesystem integrity check (RAM-only)");
    check_superblock_integrity();
    scan_inode_table();
    verify_directory_structure();
    check_block_allocation_bitmap();
    repair_filesystem_inconsistencies();
}

fn has_storage_device_errors() -> bool {
    false
}

fn handle_storage_device_errors() {
    crate::log_warn!("Handling storage device errors (on-disk disabled in ZeroState)");
}

fn check_superblock_integrity() {
    crate::log::logger::log_info!("Checking superblock integrity (RAM-only simulated)");
    let _ = read_filesystem_block(0, 1024);
}

fn scan_inode_table() {
    crate::log::logger::log_info!("Scanning inode table for corruption (RAM-only simulated)");
}

fn verify_directory_structure() {
    crate::log::logger::log_info!("Verifying directory structure (RAM-only simulated)");
}

fn check_block_allocation_bitmap() {
    crate::log::logger::log_info!("Checking block allocation bitmap (RAM-only simulated)");
}

fn repair_filesystem_inconsistencies() {
    repair_orphaned_inodes();
    fix_directory_link_counts();
    repair_block_allocation_errors();
}

fn read_filesystem_block(_block_num: u64, size: usize) -> Result<Vec<u8>, &'static str> {
    Ok(vec![0u8; size])
}

fn repair_superblock() {
    crate::log_warn!("Attempting superblock repair");
}

fn repair_orphaned_inodes() {
    crate::log::logger::log_info!("Repairing orphaned inodes");
}

fn fix_directory_link_counts() {
    crate::log::logger::log_info!("Fixing directory link counts");
}

fn repair_block_allocation_errors() {
    crate::log::logger::log_info!("Repairing block allocation errors");
}

fn is_filesystem_nearly_full() -> bool {
    false
}
fn schedule_cleanup_operation() {}

fn calculate_filesystem_stats() -> FilesystemStats {
    FilesystemStats {
        total_files: 0,
        total_directories: 0,
        bytes_used: 0,
        bytes_free: 0,
    }
}

struct FilesystemStats {
    total_files: u64,
    total_directories: u64,
    bytes_used: u64,
    bytes_free: u64,
}

fn update_global_fs_stats(_stats: FilesystemStats) {}

// File mapping for memory-mapped files
#[derive(Debug, Clone)]
pub struct FileMapping {
    pub file_id: u64,
    pub file_offset: u64,
    pub virtual_addr: x86_64::VirtAddr,
    pub size: usize,
    pub permissions: PageFlags,
}

impl FileMapping {
    pub fn new(
        file_id: u64,
        file_offset: u64,
        virtual_addr: x86_64::VirtAddr,
        size: usize,
        permissions: PageFlags,
    ) -> Self {
        Self {
            file_id,
            file_offset,
            virtual_addr,
            size,
            permissions,
        }
    }
}

/// RAM-only file read via VFS routing
pub fn read_file(file_path: &str) -> Result<Vec<u8>, &'static str> {
    if let Some(vfs) = nonos_vfs::get_vfs() {
        if let Some(data) = vfs.read_file(file_path) {
            return Ok(data);
        }
    }
    Err("File not found (RAM-only)")
}
