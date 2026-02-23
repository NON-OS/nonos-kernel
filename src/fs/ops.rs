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

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{compiler_fence, Ordering};

use super::manager::get_filesystem_manager;
use super::{cache, cryptofs, internal, ramfs, vfs};

pub fn init() {
    vfs::init_vfs();
    let _ = cryptofs::init_cryptofs(1024 * 1024, 4096);
    let _ = ramfs::init_nonos_filesystem();
    cache::init_all_caches();
    crate::log::logger::log_info!("Filesystem subsystem initialized (RAM-only mode)");
}

pub fn read_file(file_path: &str) -> Result<Vec<u8>, &'static str> {
    vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .read_file(file_path)
        .map_err(|e| e.as_str())
}

pub fn read_file_bytes(file_path: &str) -> Result<Vec<u8>, &'static str> {
    read_file(file_path)
}

pub fn write_file(file_path: &str, data: &[u8]) -> Result<(), &'static str> {
    if let Some(vfs) = vfs::get_vfs() {
        vfs.write_file(file_path, data).map_err(|e| e.as_str())
    } else {
        ramfs::write_file(file_path, data).map_err(|e| e.as_str())
    }
}

pub fn is_directory(path: &str) -> bool {
    vfs::get_vfs()
        .and_then(|vfs| vfs.stat(path).ok())
        .map(|meta| meta.file_type == super::vfs::FileType::Directory)
        .unwrap_or(false)
}

pub fn run_filesystem_sync() {
    internal::flush_dirty_pages();

    if let Some(vfs_ref) = vfs::get_vfs() {
        vfs_ref.sync_metadata();
    }

    if let Some(cryptofs_ref) = cryptofs::get_cryptofs() {
        cryptofs_ref.sync_all();
    }

    internal::sync_all_mounted_filesystems();

    if let Some(manager) = get_filesystem_manager() {
        manager.write().increment_syncs();
    }

    crate::log::logger::log_info!("Filesystem sync completed");
}

const MAX_OPERATIONS_PER_BATCH: usize = 64;

pub fn process_pending_operations() {
    let mut processed = 0;

    if let Some(vfs_ref) = vfs::get_vfs_mut() {
        processed += vfs_ref.process_pending_operations(MAX_OPERATIONS_PER_BATCH);
    }

    if let Some(cryptofs_ref) = cryptofs::get_cryptofs() {
        let remaining = MAX_OPERATIONS_PER_BATCH.saturating_sub(processed);
        if remaining > 0 {
            processed += cryptofs_ref.process_pending_operations(remaining);
        }
    }

    let remaining = MAX_OPERATIONS_PER_BATCH.saturating_sub(processed);
    if remaining > 0 {
        processed += internal::process_file_cache_writeback(remaining);
    }

    let remaining = MAX_OPERATIONS_PER_BATCH.saturating_sub(processed);
    if remaining > 0 {
        processed += internal::process_dentry_cache_updates(remaining);
    }

    let remaining = MAX_OPERATIONS_PER_BATCH.saturating_sub(processed);
    if remaining > 0 {
        processed += cache::process_inode_cache_maintenance(remaining);
    }

    if processed > 0 {
        crate::log_debug!("Processed {} filesystem operations", processed);
    }
}

pub fn clear_caches() {
    vfs::clear_vfs_caches();
    cryptofs::clear_crypto_state();
    cache::clear_all_caches();
    compiler_fence(Ordering::SeqCst);
    crate::log::logger::log_info!("Filesystem caches cleared (ZeroState wipe)");
}

pub fn mkdir(path: &str, _mode: u32) -> Result<(), &'static str> {
    vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .mkdir_all(path)
        .map_err(|e| e.as_str())
}

pub fn rmdir(path: &str) -> Result<(), &'static str> {
    vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .rmdir(path)
        .map_err(|e| e.as_str())
}

pub fn unlink(path: &str) -> Result<(), &'static str> {
    vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .unlink(path)
        .map_err(|e| e.as_str())
}

pub fn rename(old_path: &str, new_path: &str) -> Result<(), &'static str> {
    vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .rename(old_path, new_path)
        .map_err(|e| e.as_str())
}

pub fn symlink(target: &str, linkpath: &str) -> Result<(), &'static str> {
    if target.is_empty() || linkpath.is_empty() {
        return Err("Invalid path");
    }

    let symlink_content = alloc::format!("SYMLINK:{}", target);
    ramfs::NONOS_FILESYSTEM
        .create_file(linkpath, symlink_content.as_bytes())
        .map_err(|e| e.as_str())
}

pub fn readlink(path: &str) -> Result<alloc::string::String, &'static str> {
    let data = ramfs::NONOS_FILESYSTEM
        .read_file(path)
        .map_err(|e| e.as_str())?;

    let content = core::str::from_utf8(&data).map_err(|_| "Invalid symlink content")?;

    if let Some(target) = content.strip_prefix("SYMLINK:") {
        Ok(alloc::string::String::from(target))
    } else {
        Err("Not a symbolic link")
    }
}

pub fn link(old_path: &str, new_path: &str) -> Result<(), &'static str> {
    let data = ramfs::NONOS_FILESYSTEM
        .read_file(old_path)
        .map_err(|e| e.as_str())?;

    ramfs::NONOS_FILESYSTEM
        .create_file(new_path, &data)
        .map_err(|e| e.as_str())
}

pub fn chmod(path: &str, mode: u32) -> Result<(), &'static str> {
    if !ramfs::NONOS_FILESYSTEM.exists(path) {
        return Err("File not found");
    }

    let _ = mode;
    Ok(())
}

pub fn chown(path: &str, _owner: u32, _group: u32) -> Result<(), &'static str> {
    if !ramfs::NONOS_FILESYSTEM.exists(path) {
        return Err("File not found");
    }

    Ok(())
}

pub fn truncate(path: &str, length: u64) -> Result<(), &'static str> {
    let mut data = ramfs::NONOS_FILESYSTEM
        .read_file(path)
        .map_err(|e| e.as_str())?;

    let len = length as usize;
    if len < data.len() {
        data.truncate(len);
    } else if len > data.len() {
        data.resize(len, 0);
    }

    ramfs::write_file(path, &data).map_err(|e| e.as_str())
}

pub fn mount(source: Option<&str>, target: &str, fstype: Option<&str>) -> Result<(), &'static str> {
    let fs_type = match fstype {
        Some("ramfs") | Some("tmpfs") | None => vfs::FileSystemType::RamFs,
        Some("cryptofs") => vfs::FileSystemType::CryptoFS,
        Some(_) => return Err("Unsupported filesystem type in ZeroState mode"),
    };

    let _ = source;

    vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .mount(target, fs_type);

    Ok(())
}

pub fn umount(target: &str) -> Result<(), &'static str> {
    let vfs = vfs::get_vfs().ok_or("VFS not initialized")?;

    let mounts = vfs.mounts();
    if !mounts.iter().any(|m| m.mount_path == target) {
        return Err("Not mounted");
    }

    let files = ramfs::NONOS_FILESYSTEM.list_files();
    for file in files {
        if file.starts_with(target) {
            let _ = ramfs::NONOS_FILESYSTEM.delete_file(&file);
        }
    }

    Ok(())
}

pub fn mknod(path: &str, mode: u32, dev: u64) -> Result<(), &'static str> {
    let dev_info = alloc::format!("DEVNODE:mode={:o},dev={}", mode, dev);
    ramfs::NONOS_FILESYSTEM
        .create_file(path, dev_info.as_bytes())
        .map_err(|e| e.as_str())
}

pub fn set_times(path: &str, times: &[u64; 2]) -> Result<(), &'static str> {
    if !ramfs::NONOS_FILESYSTEM.exists(path) {
        return Err("File not found");
    }

    let _ = times;
    Ok(())
}

pub fn set_times_at(fd: i32, path: &str, times: &[u64; 2]) -> Result<(), &'static str> {
    if fd == -100 {
        return set_times(path, times);
    }

    let base_path = super::fd::fd_get_path(fd).map_err(|e| e.as_str())?;
    let full_path = super::path::join(&base_path, path);
    set_times(&full_path, times)
}
