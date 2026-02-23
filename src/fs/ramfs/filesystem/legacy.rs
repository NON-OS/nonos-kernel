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

use alloc::string::String;
use alloc::vec::Vec;

use super::global::{create_file, read_file, write_file, delete_file, list_dir};

pub(crate) fn create_file_legacy(name: &str, data: &[u8]) -> Result<(), &'static str> {
    create_file(name, data).map_err(|e| e.as_str())
}

pub(crate) fn read_file_legacy(name: &str) -> Result<Vec<u8>, &'static str> {
    read_file(name).map_err(|e| e.as_str())
}

pub(crate) fn write_file_legacy(name: &str, data: &[u8]) -> Result<(), &'static str> {
    write_file(name, data).map_err(|e| e.as_str())
}

pub(crate) fn delete_file_legacy(name: &str) -> Result<(), &'static str> {
    delete_file(name).map_err(|e| e.as_str())
}

pub(crate) fn list_dir_legacy(path: &str) -> Result<Vec<String>, &'static str> {
    list_dir(path).map_err(|e| e.as_str())
}
