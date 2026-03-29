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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static FILE_HANDLES: spin::RwLock<BTreeMap<u64, FileHandle>> = spin::RwLock::new(BTreeMap::new());

pub(super) struct FileHandle { path: String, offset: usize }

pub(super) fn open_handle(path: &str, flags: i32) -> Option<u64> {
    if !crate::fs::ramfs::exists(path) && (flags & 0x40) == 0 { return None; }
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    FILE_HANDLES.write().insert(handle, FileHandle { path: String::from(path), offset: 0 });
    Some(handle)
}

pub(super) fn read_handle(handle: u64, count: usize) -> Option<Vec<u8>> {
    let mut handles = FILE_HANDLES.write();
    let fh = handles.get_mut(&handle)?;
    let data = crate::fs::read_file(&fh.path).ok()?;
    let start = fh.offset.min(data.len());
    let end = (start + count).min(data.len());
    fh.offset = end;
    Some(data[start..end].to_vec())
}

pub(super) fn write_handle(handle: u64, data: &[u8]) -> Option<usize> {
    let mut handles = FILE_HANDLES.write();
    let fh = handles.get_mut(&handle)?;
    crate::fs::write_file(&fh.path, data).ok()?;
    fh.offset += data.len();
    Some(data.len())
}

pub(super) fn close_handle(handle: u64) -> bool { FILE_HANDLES.write().remove(&handle).is_some() }
