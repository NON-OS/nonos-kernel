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

use crate::firmware::types::FirmwareType;
use super::metadata::FirmwareMetadata;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseResult { Success, NotFound, AlreadyExists, DatabaseFull, InvalidEntry }

#[derive(Debug, Clone)]
pub struct FirmwareDatabase { entries: [Option<DatabaseEntry>; 256], count: usize }

#[derive(Debug, Clone)]
struct DatabaseEntry { firmware_type: FirmwareType, metadata: FirmwareMetadata, data_ptr: u64, data_size: u32 }

pub fn register_firmware(db: &mut FirmwareDatabase, firmware_type: FirmwareType, metadata: FirmwareMetadata, data: &[u8]) -> DatabaseResult {
    if db.count >= db.entries.len() { return DatabaseResult::DatabaseFull; }
    if lookup_firmware(db, firmware_type).is_some() { return DatabaseResult::AlreadyExists; }
    if data.is_empty() { return DatabaseResult::InvalidEntry; }
    let entry = DatabaseEntry { firmware_type, metadata, data_ptr: data.as_ptr() as u64, data_size: data.len() as u32 };
    for slot in &mut db.entries { if slot.is_none() { *slot = Some(entry); db.count += 1; return DatabaseResult::Success; } }
    DatabaseResult::DatabaseFull
}

pub fn lookup_firmware(db: &FirmwareDatabase, firmware_type: FirmwareType) -> Option<&DatabaseEntry> {
    db.entries.iter().filter_map(|entry| entry.as_ref()).find(|entry| entry.firmware_type == firmware_type)
}

impl FirmwareDatabase {
    pub const fn new() -> Self { Self { entries: [None; 256], count: 0 } }
    pub fn get_count(&self) -> usize { self.count }
    pub fn get_capacity(&self) -> usize { self.entries.len() }
    pub fn is_full(&self) -> bool { self.count >= self.entries.len() }
    pub fn contains(&self, firmware_type: FirmwareType) -> bool { lookup_firmware(self, firmware_type).is_some() }
    pub fn get_firmware_data(&self, firmware_type: FirmwareType) -> Option<&[u8]> {
        let entry = lookup_firmware(self, firmware_type)?;
        unsafe { Some(core::slice::from_raw_parts(entry.data_ptr as *const u8, entry.data_size as usize)) }
    }
    pub fn get_metadata(&self, firmware_type: FirmwareType) -> Option<&FirmwareMetadata> { lookup_firmware(self, firmware_type).map(|entry| &entry.metadata) }
}