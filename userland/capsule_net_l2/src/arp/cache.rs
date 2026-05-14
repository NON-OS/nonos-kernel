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

use crate::ethernet::MacAddress;

pub const ENTRY_CAP: usize = 64;

#[derive(Clone, Copy, Debug)]
pub struct Entry {
    pub ipv4: [u8; 4],
    pub mac: MacAddress,
    pub age_ticks: u32,
}

pub struct Cache {
    entries: [Option<Entry>; ENTRY_CAP],
    len: usize,
}

impl Cache {
    pub const fn new() -> Self {
        Self { entries: [None; ENTRY_CAP], len: 0 }
    }

    pub fn lookup(&self, ipv4: &[u8; 4]) -> Option<MacAddress> {
        self.entries
            .iter()
            .filter_map(|e| e.as_ref())
            .find(|e| e.ipv4 == *ipv4)
            .map(|e| e.mac)
    }

    pub fn insert(&mut self, ipv4: [u8; 4], mac: MacAddress) {
        for slot in &mut self.entries {
            if let Some(e) = slot {
                if e.ipv4 == ipv4 {
                    e.mac = mac;
                    e.age_ticks = 0;
                    return;
                }
            }
        }
        if let Some(slot) = self.entries.iter_mut().find(|e| e.is_none()) {
            *slot = Some(Entry { ipv4, mac, age_ticks: 0 });
            self.len += 1;
            return;
        }
        self.evict_oldest();
        if let Some(slot) = self.entries.iter_mut().find(|e| e.is_none()) {
            *slot = Some(Entry { ipv4, mac, age_ticks: 0 });
            self.len += 1;
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter_map(|e| e.as_ref())
    }

    pub fn tick(&mut self) {
        for slot in &mut self.entries {
            if let Some(e) = slot {
                e.age_ticks = e.age_ticks.saturating_add(1);
            }
        }
    }

    fn evict_oldest(&mut self) {
        let mut oldest_idx = None;
        let mut oldest_age = 0u32;
        for (i, slot) in self.entries.iter().enumerate() {
            if let Some(e) = slot {
                if e.age_ticks >= oldest_age {
                    oldest_age = e.age_ticks;
                    oldest_idx = Some(i);
                }
            }
        }
        if let Some(i) = oldest_idx {
            self.entries[i] = None;
            self.len -= 1;
        }
    }
}
