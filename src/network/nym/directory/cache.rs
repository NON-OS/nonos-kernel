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

use crate::network::nym::types::{Gateway, MixNode};
use alloc::vec::Vec;
use spin::{Mutex, Once};

const CACHE_TTL_MS: u64 = 300_000;

static DIRECTORY_CACHE: Once<Mutex<DirectoryCache>> = Once::new();

pub struct DirectoryCache {
    pub mixnodes: Vec<MixNode>,
    pub gateways: Vec<Gateway>,
    pub last_mixnode_fetch: u64,
    pub last_gateway_fetch: u64,
}

pub fn get_directory_cache() -> &'static Mutex<DirectoryCache> {
    DIRECTORY_CACHE.call_once(|| Mutex::new(DirectoryCache::new()))
}

impl DirectoryCache {
    pub fn new() -> Self {
        Self {
            mixnodes: Vec::new(),
            gateways: Vec::new(),
            last_mixnode_fetch: 0,
            last_gateway_fetch: 0,
        }
    }

    pub fn is_mixnodes_stale(&self) -> bool {
        let now = crate::time::timestamp_millis();
        now.saturating_sub(self.last_mixnode_fetch) > CACHE_TTL_MS
    }

    pub fn is_gateways_stale(&self) -> bool {
        let now = crate::time::timestamp_millis();
        now.saturating_sub(self.last_gateway_fetch) > CACHE_TTL_MS
    }

    pub fn clear(&mut self) {
        self.mixnodes.clear();
        self.gateways.clear();
        self.last_mixnode_fetch = 0;
        self.last_gateway_fetch = 0;
    }

    pub fn mixnode_count(&self) -> usize {
        self.mixnodes.len()
    }

    pub fn gateway_count(&self) -> usize {
        self.gateways.len()
    }
}
