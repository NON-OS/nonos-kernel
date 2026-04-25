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
use super::optimize::CompressionType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageResult { Success, NotFound, StorageFull, CorruptedData, AccessDenied }

#[derive(Debug, Clone)]
pub struct StorageCache { entries: [CacheEntry; 128], storage_used: u64, storage_limit: u64 }

#[derive(Debug, Clone)]
pub struct CacheEntry { firmware_type: FirmwareType, storage_offset: u64, compressed_size: u32, original_size: u32, compression_type: CompressionType, checksum: u32, valid: bool }

pub fn persist_cache(storage: &mut StorageCache, firmware_type: FirmwareType, data: &[u8], compression: CompressionType) -> StorageResult {
    if storage.storage_used + data.len() as u64 > storage.storage_limit { return StorageResult::StorageFull; }
    let compressed_data = super::optimize::compress_firmware(data, compression);
    let checksum = calculate_checksum(&compressed_data);
    let offset = allocate_storage_space(storage, compressed_data.len() as u32);
    if offset == 0 { return StorageResult::StorageFull; }
    let entry = CacheEntry { firmware_type, storage_offset: offset, compressed_size: compressed_data.len() as u32, original_size: data.len() as u32, compression_type: compression, checksum, valid: true };
    if let Some(slot) = find_empty_slot(storage) { storage.entries[slot] = entry; storage.storage_used += compressed_data.len() as u64; StorageResult::Success } else { StorageResult::StorageFull }
}

pub fn load_cache(storage: &StorageCache, firmware_type: FirmwareType) -> Result<alloc::vec::Vec<u8>, StorageResult> {
    let entry = storage.entries.iter().find(|entry| entry.valid && entry.firmware_type == firmware_type).ok_or(StorageResult::NotFound)?;
    let compressed_data = read_from_storage(entry.storage_offset, entry.compressed_size)?;
    if calculate_checksum(&compressed_data) != entry.checksum { return Err(StorageResult::CorruptedData); }
    super::optimize::decompress_firmware(&compressed_data, entry.compression_type).map_err(|_| StorageResult::CorruptedData)
}

impl StorageCache {
    pub const fn new(storage_limit: u64) -> Self { Self { entries: [const { CacheEntry::empty() }; 128], storage_used: 0, storage_limit } }
    pub fn get_usage(&self) -> f32 { if self.storage_limit == 0 { 0.0 } else { self.storage_used as f32 / self.storage_limit as f32 } }
    pub fn contains(&self, firmware_type: FirmwareType) -> bool { self.entries.iter().any(|entry| entry.valid && entry.firmware_type == firmware_type) }
}

impl CacheEntry {
    const fn empty() -> Self { Self { firmware_type: FirmwareType::Unknown, storage_offset: 0, compressed_size: 0, original_size: 0, compression_type: CompressionType::None, checksum: 0, valid: false } }
}

fn find_empty_slot(storage: &StorageCache) -> Option<usize> { storage.entries.iter().position(|entry| !entry.valid) }
fn allocate_storage_space(storage: &mut StorageCache, size: u32) -> u64 { static mut NEXT_OFFSET: u64 = 1024; unsafe { let offset = NEXT_OFFSET; NEXT_OFFSET += size as u64; if NEXT_OFFSET <= storage.storage_limit { offset } else { 0 } } }
fn read_from_storage(_offset: u64, size: u32) -> Result<alloc::vec::Vec<u8>, StorageResult> { Ok(alloc::vec![0u8; size as usize]) }
fn calculate_checksum(data: &[u8]) -> u32 { data.iter().fold(0u32, |acc, &byte| acc.wrapping_add(u32::from(byte))) }