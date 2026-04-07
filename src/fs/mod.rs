// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

pub mod cache;
pub mod cryptofs;
pub mod devfs;
pub mod ext4;
pub mod fd;
pub mod path;
pub mod pipe;
pub mod procfs;
pub mod ramfs;
pub mod storage;
pub mod sysfs;
pub mod utils;
pub mod vfs;
pub mod vfs_redirect;

mod errors;
mod internal;
mod manager;
mod mapping;
mod ops;

#[cfg(test)]
mod tests;

pub use vfs as nonos_vfs;
pub use ramfs as nonos_filesystem;
pub use cryptofs as nonos_crypto;
pub use vfs as nvfs;

pub use vfs::{
    CowPageRef, DeviceOperations, FileBuffer, FileCacheEntry, FileMetadata, FileMode,
    FileSystemOperations, FileSystemType, FileType, IoOperation, IoRequest, IoStatistics,
    MountPoint, VfsInode, VirtualFileSystem, VfsError, VfsResult,
    get_vfs, get_vfs_mut, init_vfs,
};

pub use cryptofs::{
    CryptoFileSystem, CryptoFsStatistics, CryptoFsError, CryptoResult,
    create_encrypted_file, create_ephemeral_file, get_cryptofs, init_cryptofs,
    read_encrypted, write_encrypted, delete_encrypted, clear_crypto_state,
    rotate_file_key, nonce_counter_warning,
};

pub use ramfs::{FsError, FsResult};

pub use fd::{
    open_file_syscall, read_file_descriptor, write_file_descriptor, close_file_descriptor,
    stat_file_syscall, fstat_file_syscall, rmdir_syscall, unlink_syscall, sync_all,
    FdError, FdResult,
};

pub use path::{
    PathError, PathResult, cstr_to_string, normalize_path, validate_path,
    validate_path_secure, is_absolute, is_relative, parent, file_name, extension,
    join, join_normalize, join_secure, components, MAX_PATH_LEN,
};

pub use cache::{
    get_cache_statistics, get_cache_hit_ratio, init_all_caches, clear_all_caches,
    get_full_cache_statistics, CacheStats, CACHE_STATS,
};

pub use utils::{
    list_hidden_files, scan_for_sensitive_files, is_sensitive_file, is_hidden_file,
    classify_file, scan_files_with_config, ScanConfig, ScanResult, FileClassification,
    FileCategory, SensitivityLevel, UtilsError, UtilsResult,
};

pub use storage::{
    get_storage_stats, get_total_used_bytes, get_total_available_bytes,
    get_storage_usage_percent, get_filesystem_breakdown, get_storage_health,
    get_inode_stats, StorageStats, StorageHealth, StorageHealthStatus,
    FilesystemBreakdown, InodeStats, StorageQuota, StorageError, StorageResult,
};

pub use errors::{FsSubsystemError, FsSubsystemResult};
pub use manager::{FileSystemManager, FileSystemManagerStats, get_filesystem_manager, init_filesystem_manager};
pub use mapping::{FileMapping, MappingProtection};
pub use ops::{
    init, read_file, read_file_bytes, write_file, run_filesystem_sync, process_pending_operations, clear_caches,
    mkdir, rmdir, unlink, rename, symlink, readlink, link, chmod, chown, truncate, mount, umount, mknod, set_times, set_times_at,
    is_directory,
};

pub fn allocate_fd() -> Result<i32, i32> {
    fd::fd_open_raw(core::ptr::null(), 0).map_err(|_| -24)
}

pub fn pread(fd: i32, buf: &mut [u8], offset: u64) -> Result<usize, i32> {
    let orig_pos = fd::fd_get_offset(fd).map_err(|_| -9i32)? as i64;
    fd::fd_lseek(fd, offset as i64, 0).map_err(|_| -9i32)?;
    let result = fd::fd_read(fd, buf.as_mut_ptr(), buf.len());
    let _ = fd::fd_lseek(fd, orig_pos, 0);
    result.map_err(|_| -5)
}

pub fn pwrite(fd: i32, buf: &[u8], offset: u64) -> Result<usize, i32> {
    let orig_pos = fd::fd_get_offset(fd).map_err(|_| -9i32)? as i64;
    fd::fd_lseek(fd, offset as i64, 0).map_err(|_| -9i32)?;
    let result = fd::fd_write(fd, buf.as_ptr(), buf.len());
    let _ = fd::fd_lseek(fd, orig_pos, 0);
    result.map_err(|_| -5)
}

pub fn get_file_size(fd: i32) -> Result<u64, i32> {
    let mut stat_buf = [0u8; 48];
    fd::fd_fstat(fd, stat_buf.as_mut_ptr()).map_err(|_| -9)?;
    let size = u64::from_le_bytes(stat_buf[16..24].try_into().unwrap_or([0; 8]));
    Ok(size)
}

pub fn register_pipe_reader<T>(_fd: i32, _reader: T) {}
pub fn register_pipe_writer<T>(_fd: i32, _writer: T) {}
pub fn set_cloexec(fd: i32, cloexec: bool) { let _ = fd::fd_set_cloexec(fd, cloexec); }
pub fn is_pipe_fd(_fd: i32) -> bool { false }
pub fn get_pipe_buffer_size(_fd: i32) -> Result<usize, i32> { Ok(crate::fs::pipe::PIPE_BUF_SIZE) }
pub fn set_pipe_buffer_size(_fd: i32, size: usize) -> Result<usize, i32> { Ok(size.min(crate::fs::pipe::PIPE_BUF_SIZE * 16)) }
pub fn get_process_fds(pid: i32) -> Result<alloc::vec::Vec<i32>, i32> {
    let proc = crate::process::get_process(pid as u32).ok_or(-3)?;
    Ok(proc.fd_table.all_fds())
}
pub fn get_process_fd(pid: i32, fd: i32) -> Option<FdInfo> {
    let proc = crate::process::get_process(pid as u32)?;
    let entry = proc.fd_table.get(fd)?;
    Some(FdInfo { path: alloc::format!("fd:{}", fd), flags: entry.flags, mode: 0, position: 0, mount_id: 0, inode: entry.internal_id as u64 })
}

use alloc::sync::Arc;
use spin::Mutex;
use alloc::collections::BTreeMap;

static UNIX_SOCKETS: Mutex<BTreeMap<i32, Arc<crate::network::unix::UnixSocket>>> = Mutex::new(BTreeMap::new());

pub fn register_unix_socket(fd: i32, socket: Arc<crate::network::unix::UnixSocket>) { UNIX_SOCKETS.lock().insert(fd, socket); }
pub fn get_unix_socket(fd: i32) -> Option<Arc<crate::network::unix::UnixSocket>> { UNIX_SOCKETS.lock().get(&fd).cloned() }
pub fn close_unix_socket(fd: i32) { UNIX_SOCKETS.lock().remove(&fd); }

pub struct FdInfo {
    pub path: alloc::string::String,
    pub flags: u32,
    pub mode: u32,
    pub position: u64,
    pub mount_id: u32,
    pub inode: u64,
}
