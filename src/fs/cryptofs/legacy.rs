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

use super::ops::{
    create_encrypted_file, create_ephemeral_file, read_encrypted,
    write_encrypted, delete_encrypted,
};

pub fn create_encrypted_file_legacy(parent_inode: u64, path: &str, caps: &[u8]) -> Result<u64, &'static str> {
    create_encrypted_file(parent_inode, path, caps).map_err(|e| e.as_str())
}

pub fn create_ephemeral_file_legacy(path: &str, data: &[u8]) -> Result<u64, &'static str> {
    create_ephemeral_file(path, data).map_err(|e| e.as_str())
}

pub fn read_encrypted_legacy(path: &str) -> Result<Vec<u8>, &'static str> {
    read_encrypted(path).map_err(|e| e.as_str())
}

pub fn write_encrypted_legacy(path: &str, data: &[u8]) -> Result<(), &'static str> {
    write_encrypted(path, data).map_err(|e| e.as_str())
}

pub fn delete_encrypted_legacy(path: &str) -> Result<(), &'static str> {
    delete_encrypted(path).map_err(|e| e.as_str())
}
