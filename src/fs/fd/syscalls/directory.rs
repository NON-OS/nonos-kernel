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

use crate::fs::fd::types::cstr_to_string;

pub fn mkdir_syscall(pathname: *const u8) -> Result<(), &'static str> {
    let path = cstr_to_string(pathname).map_err(|e| e.as_str())?;
    crate::fs::vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .mkdir_all(&path)
        .map_err(|e| e.as_str())
}

pub fn rename_syscall(oldpath: *const u8, newpath: *const u8) -> Result<(), &'static str> {
    let old = cstr_to_string(oldpath).map_err(|e| e.as_str())?;
    let new = cstr_to_string(newpath).map_err(|e| e.as_str())?;
    crate::fs::vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .rename(&old, &new)
        .map_err(|e| e.as_str())
}

pub fn rmdir_syscall(pathname: *const u8) -> Result<(), &'static str> {
    if pathname.is_null() {
        return Err("Invalid path");
    }
    let path = cstr_to_string(pathname).map_err(|e| e.as_str())?;
    crate::fs::vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .rmdir(&path)
        .map_err(|e| e.as_str())
}

pub fn unlink_syscall(pathname: *const u8) -> Result<(), &'static str> {
    if pathname.is_null() {
        return Err("Invalid path");
    }
    let path = cstr_to_string(pathname).map_err(|e| e.as_str())?;
    crate::fs::vfs::get_vfs()
        .ok_or("VFS not initialized")?
        .unlink(&path)
        .map_err(|e| e.as_str())
}
