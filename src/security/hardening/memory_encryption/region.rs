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
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use spin::RwLock;
use super::types::{EncryptedRegion, EncryptionError};
use super::engine::{STATS, generate_key_id};

static PROTECTED_REGIONS: RwLock<BTreeMap<u64, EncryptedRegion>> = RwLock::new(BTreeMap::new());

pub fn register_region(start: u64, size: usize) -> Result<u64, EncryptionError> {
    if !super::engine::is_initialized() { return Err(EncryptionError::NotInitialized); }
    if size == 0 { return Err(EncryptionError::InvalidRegion); }
    let mut regions = PROTECTED_REGIONS.write();
    if regions.contains_key(&start) { return Err(EncryptionError::AlreadyProtected); }
    let key_id = generate_key_id();
    let region = EncryptedRegion::new(start, size, key_id);
    regions.insert(start, region);
    STATS.regions_protected.fetch_add(1, Ordering::Relaxed);
    Ok(key_id)
}

pub fn unregister_region(start: u64) -> Result<(), EncryptionError> {
    let mut regions = PROTECTED_REGIONS.write();
    if regions.remove(&start).is_some() {
        STATS.regions_protected.fetch_sub(1, Ordering::Relaxed);
        Ok(())
    } else { Err(EncryptionError::RegionNotFound) }
}

pub fn get_region(start: u64) -> Option<EncryptedRegion> { PROTECTED_REGIONS.read().get(&start).cloned() }
pub fn update_region(region: EncryptedRegion) { PROTECTED_REGIONS.write().insert(region.start, region); }
pub fn get_protected_regions() -> Vec<EncryptedRegion> { PROTECTED_REGIONS.read().values().cloned().collect() }
pub fn is_region_protected(addr: u64) -> bool {
    let regions = PROTECTED_REGIONS.read();
    for r in regions.values() {
        if addr >= r.start && addr < r.start + r.size as u64 { return true; }
    }
    false
}
