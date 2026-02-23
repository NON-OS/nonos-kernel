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
pub mod fd;
pub mod path;
pub mod ramfs;
pub mod storage;
pub mod utils;
pub mod vfs;

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
