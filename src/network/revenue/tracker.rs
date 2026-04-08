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
use spin::RwLock;
use super::types::{RevenueEntry, RevenueError, RevenueSplit};

struct Tracker { entries: BTreeMap<[u8; 32], RevenueEntry>, total: u128 }
static TRACK: RwLock<Option<Tracker>> = RwLock::new(None);

pub fn init() { *TRACK.write() = Some(Tracker { entries: BTreeMap::new(), total: 0 }); }

pub fn record_payment(capsule_id: &[u8; 32], amount: u128) {
    if let Some(t) = TRACK.write().as_mut() {
        let entry = t.entries.entry(*capsule_id).or_insert_with(|| RevenueEntry::new(*capsule_id));
        entry.total_revenue += amount;
        t.total += amount;
    }
}

pub fn record_distribution(capsule_id: &[u8; 32], split: &RevenueSplit) {
    if let Some(t) = TRACK.write().as_mut() {
        if let Some(entry) = t.entries.get_mut(capsule_id) {
            entry.developer_paid += split.developer;
            entry.nft_pool_paid += split.nft_pool;
            entry.treasury_paid += split.treasury;
            entry.last_distribution = crate::time::unix_timestamp();
        }
    }
}

pub fn get_entry(capsule_id: &[u8; 32]) -> Option<RevenueEntry> {
    TRACK.read().as_ref()?.entries.get(capsule_id).copied()
}

pub fn get_pending(capsule_id: &[u8; 32]) -> u128 {
    get_entry(capsule_id).map(|e| e.pending()).unwrap_or(0)
}

pub fn total_revenue() -> u128 { TRACK.read().as_ref().map(|t| t.total).unwrap_or(0) }

pub fn capsule_count() -> usize { TRACK.read().as_ref().map(|t| t.entries.len()).unwrap_or(0) }

pub fn list_capsules() -> alloc::vec::Vec<[u8; 32]> {
    TRACK.read().as_ref().map(|t| t.entries.keys().copied().collect()).unwrap_or_default()
}
