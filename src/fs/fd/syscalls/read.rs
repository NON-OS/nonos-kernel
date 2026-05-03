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
use crate::fs::fd::table::{get_entry_read, get_entry_write, is_stdio, validate_fd_range};
use crate::fs::fd::types::{copy_to_user_ptr, OpenBackend, OpenFile};
use crate::fs::ramfs_capsule::client as capsule_client;

use super::stdio::read_stdin;

fn record_read_io(bytes: usize) {
    if let Some(pid) = crate::process::current_pid() {
        if let Some(proc) = crate::process::get_process(pid) {
            let mut io = proc.io_stats.lock();
            io.rchar += bytes as u64;
            io.syscr += 1;
            io.read_bytes += bytes as u64;
        }
    }
}

pub(crate) fn read_file_impl(entry: &mut OpenFile, buf: *mut u8, count: usize) -> FdResult<usize> {
    if !entry.is_readable() {
        return Err(FdError::NotReadable);
    }
    match entry.backend {
        OpenBackend::KernelRamfs => read_kernel(entry, buf, count),
        OpenBackend::CapsuleRamfs => read_capsule(entry, buf, count),
    }
}

fn read_kernel(entry: &mut OpenFile, buf: *mut u8, count: usize) -> FdResult<usize> {
    let data = crate::fs::read_file(&entry.path)?;
    let start = entry.offset.min(data.len());
    let remaining = data.len().saturating_sub(start);
    let to_copy = remaining.min(count);
    if to_copy > 0 {
        // SAFETY: ek@nonos.systems — caller guarantees buf points to a
        // user-writable region of at least `count` bytes; the slice
        // length is bounded above by `count`.
        unsafe {
            copy_to_user_ptr(&data[start..start + to_copy], buf)?;
        }
        entry.offset = entry.offset.saturating_add(to_copy);
    }
    Ok(to_copy)
}

fn read_capsule(entry: &mut OpenFile, buf: *mut u8, count: usize) -> FdResult<usize> {
    let handle = entry.remote_handle.ok_or(FdError::FsError("capsule fd missing handle"))?;
    let generation =
        entry.capsule_generation.ok_or(FdError::FsError("capsule fd missing generation"))?;
    let bytes = capsule_client::read(handle, generation, entry.offset as u64, count as u32)
        .map_err(FdError::from)?;
    if !bytes.is_empty() {
        // SAFETY: ek@nonos.systems — caller guarantees buf points to a
        // user-writable region of at least `count` bytes; the source
        // slice length is bounded above by `count` by the capsule.
        unsafe {
            copy_to_user_ptr(&bytes, buf)?;
        }
        entry.offset = entry.offset.saturating_add(bytes.len());
    }
    Ok(bytes.len())
}

pub(crate) fn read_at_impl(
    path: &str,
    buf: *mut u8,
    count: usize,
    offset: usize,
) -> FdResult<usize> {
    let data = crate::fs::read_file(path)?;

    let start = offset.min(data.len());
    let remaining = data.len().saturating_sub(start);
    let to_copy = remaining.min(count);

    if to_copy > 0 {
        // SAFETY: ek@nonos.systems — caller guarantees buf points to a
        // user-writable region of at least `count` bytes; the slice
        // length is bounded above by `count`.
        unsafe {
            copy_to_user_ptr(&data[start..start + to_copy], buf)?;
        }
    }

    Ok(to_copy)
}

pub fn read_file_descriptor(fd: i32, buf: *mut u8, count: usize) -> Option<usize> {
    fd_read(fd, buf, count).ok()
}

pub fn fd_read(fd: i32, buf: *mut u8, count: usize) -> FdResult<usize> {
    validate_fd_range(fd)?;
    if buf.is_null() {
        return Err(FdError::NullPointer);
    }
    if count == 0 {
        return Ok(0);
    }
    let result = match fd {
        0 => read_stdin(buf, count),
        1 | 2 => Err(FdError::NotReadable),
        _ => get_entry_write(fd, |entry| read_file_impl(entry, buf, count)),
    };
    if let Ok(bytes) = &result {
        record_read_io(*bytes);
    }
    result
}

pub fn fd_read_at(fd: i32, buf: *mut u8, count: usize, offset: usize) -> FdResult<usize> {
    validate_fd_range(fd)?;

    if buf.is_null() {
        return Err(FdError::NullPointer);
    }

    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }

    let snapshot = get_entry_read(fd, |entry| {
        Ok((
            entry.path.clone(),
            entry.is_readable(),
            entry.backend,
            entry.remote_handle,
            entry.capsule_generation,
        ))
    })?;
    let (path, readable, backend, handle, generation) = snapshot;

    if !readable {
        return Err(FdError::NotReadable);
    }

    match backend {
        OpenBackend::KernelRamfs => read_at_impl(&path, buf, count, offset),
        OpenBackend::CapsuleRamfs => {
            let handle = handle.ok_or(FdError::FsError("capsule fd missing handle"))?;
            let generation = generation.ok_or(FdError::FsError("capsule fd missing generation"))?;
            let bytes = capsule_client::read(handle, generation, offset as u64, count as u32)
                .map_err(FdError::from)?;
            if !bytes.is_empty() {
                // SAFETY: ek@nonos.systems — caller guarantees buf points
                // to a user-writable region of at least `count` bytes;
                // the source slice length is bounded above by `count`.
                unsafe {
                    copy_to_user_ptr(&bytes, buf)?;
                }
            }
            Ok(bytes.len())
        }
    }
}
