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

use crate::fs::fd::error::{FdError, FdResult};
use crate::fs::fd::table::{get_entry_read, is_stdio, validate_fd_range};
use crate::fs::ramfs;

pub fn fd_sync(fd: i32) -> FdResult<()> {
    validate_fd_range(fd)?;

    if is_stdio(fd) {
        return Ok(());
    }

    let path = get_entry_read(fd, |entry| {
        if !ramfs::NONOS_FILESYSTEM.exists(&entry.path) {
            return Err(FdError::NotFound);
        }
        Ok(entry.path.clone())
    })?;

    if let Ok(info) = ramfs::NONOS_FILESYSTEM.get_file_info(&path) {
        crate::fs::cache::mark_page_clean(info.inode, 0);
    }
    crate::fs::cache::process_inode_cache_maintenance(16);

    Ok(())
}

pub fn fd_allocate(fd: i32, offset: usize, len: usize) -> FdResult<()> {
    validate_fd_range(fd)?;

    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }

    let path = get_entry_read(fd, |entry| {
        if !entry.is_writable() {
            return Err(FdError::NotWritable);
        }
        Ok(entry.path.clone())
    })?;

    let mut data = crate::fs::read_file(&path).unwrap_or_default();

    let required_size = match offset.checked_add(len) {
        Some(v) if v <= ramfs::MAX_FILE_SIZE => v,
        _ => return Err(FdError::BufferTooLarge),
    };
    if required_size > data.len() {
        data.resize(required_size, 0);
        ramfs::write_file(&path, &data).map_err(FdError::from)?;
    }

    Ok(())
}

/* DEV NOTES eK@nonos.systems
   File descriptor based chmod implementation. Validates FD, retrieves path from FD table,
   and delegates to ramfs chmod which updates file mode bits (permission mask 0o7777).
*/
pub fn fd_chmod(fd: i32, mode: u32) -> FdResult<()> {
    validate_fd_range(fd)?;

    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }

    let path = get_entry_read(fd, |entry| Ok(entry.path.clone()))?;

    ramfs::NONOS_FILESYSTEM.chmod(&path, mode).map_err(FdError::from)
}

/* DEV NOTES eK@nonos.systems
   File descriptor based chown implementation. Validates FD, retrieves path from FD table,
   and delegates to ramfs chown which updates file ownership (uid/gid).
*/
pub fn fd_chown(fd: i32, owner: u32, group: u32) -> FdResult<()> {
    validate_fd_range(fd)?;

    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }

    let path = get_entry_read(fd, |entry| Ok(entry.path.clone()))?;

    ramfs::NONOS_FILESYSTEM.chown(&path, owner, group).map_err(FdError::from)
}

/* DEV NOTES eK@nonos.systems
   Global filesystem sync. For ramfs this is a no-op since data is in memory.
   For persistent filesystems (ext4, cryptofs) this flushes dirty buffers to disk.
*/
pub fn sync_all() -> Result<(), &'static str> {
    crate::fs::internal::sync_all_mounted_filesystems();
    Ok(())
}
