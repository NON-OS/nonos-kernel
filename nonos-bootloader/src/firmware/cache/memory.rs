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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheResult { Hit, Miss, Evicted, Error, Full }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy { LeastRecentlyUsed, LeastFrequentlyUsed, FirstInFirstOut }

#[derive(Debug, Clone)]
pub struct MemoryCache { entries: [CacheEntry; 64], policy: CachePolicy, hits: u32, misses: u32 }

#[derive(Debug, Clone, Copy)]
struct CacheEntry { firmware_type: FirmwareType, data_ptr: u64, data_size: u32, access_count: u16, last_access: u32, valid: bool }

pub fn cache_firmware(cache: &mut MemoryCache, firmware_type: FirmwareType, data: &[u8]) -> CacheResult {
    if data.len() > 16 * 1024 * 1024 { return CacheResult::Error; }
    if let Some(index) = find_cache_slot(cache, firmware_type) {
        update_cache_entry(cache, index, firmware_type, data);
        return CacheResult::Hit;
    }
    if let Some(victim_index) = select_victim(cache) {
        evict_entry(cache, victim_index);
        update_cache_entry(cache, victim_index, firmware_type, data);
        CacheResult::Evicted
    } else {
        CacheResult::Full
    }
}

pub fn invalidate_cache(cache: &mut MemoryCache, firmware_type: FirmwareType) -> bool {
    for entry in &mut cache.entries { if entry.valid && entry.firmware_type == firmware_type { entry.valid = false; return true; } }
    false
}

impl MemoryCache {
    pub const fn new(policy: CachePolicy) -> Self { Self { entries: [CacheEntry::empty(); 64], policy, hits: 0, misses: 0 } }
    pub fn get_hit_rate(&self) -> f32 { if self.hits + self.misses == 0 { 0.0 } else { self.hits as f32 / (self.hits + self.misses) as f32 } }
    pub fn get_firmware(&mut self, firmware_type: FirmwareType) -> Option<&[u8]> {
        for entry in &mut self.entries { if entry.valid && entry.firmware_type == firmware_type { entry.access_count = entry.access_count.saturating_add(1); entry.last_access = get_timestamp(); self.hits += 1; return Some(unsafe { core::slice::from_raw_parts(entry.data_ptr as *const u8, entry.data_size as usize) }); } }
        self.misses += 1; None
    }
}

impl CacheEntry {
    const fn empty() -> Self { Self { firmware_type: FirmwareType::Unknown, data_ptr: 0, data_size: 0, access_count: 0, last_access: 0, valid: false } }
}

fn find_cache_slot(cache: &MemoryCache, firmware_type: FirmwareType) -> Option<usize> { cache.entries.iter().position(|entry| entry.valid && entry.firmware_type == firmware_type) }
fn select_victim(cache: &MemoryCache) -> Option<usize> {
    match cache.policy { CachePolicy::LeastRecentlyUsed => cache.entries.iter().enumerate().filter(|(_, entry)| entry.valid).min_by_key(|(_, entry)| entry.last_access).map(|(i, _)| i), CachePolicy::LeastFrequentlyUsed => cache.entries.iter().enumerate().filter(|(_, entry)| entry.valid).min_by_key(|(_, entry)| entry.access_count).map(|(i, _)| i), CachePolicy::FirstInFirstOut => cache.entries.iter().position(|entry| entry.valid) }
}
fn update_cache_entry(cache: &mut MemoryCache, index: usize, firmware_type: FirmwareType, data: &[u8]) { cache.entries[index] = CacheEntry { firmware_type, data_ptr: data.as_ptr() as u64, data_size: data.len() as u32, access_count: 1, last_access: get_timestamp(), valid: true }; }
fn evict_entry(cache: &mut MemoryCache, index: usize) { cache.entries[index].valid = false; }
fn get_timestamp() -> u32 { static mut COUNTER: u32 = 0; unsafe { COUNTER += 1; COUNTER } }