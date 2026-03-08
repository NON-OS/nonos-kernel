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

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::sync::atomic::AtomicU64;
use spin::{Mutex, RwLock};

use crate::network::onion::directory::types::{
    DirectoryAuthority, DirectoryStats, NetworkConsensus, RelayDescriptor,
};
use crate::network::onion::directory::authorities::default_authorities;
use crate::network::onion::OnionError;
use crate::crypto::vault;

pub(super) const MAX_HTTP_BODY_BYTES: usize = 5 * 1024 * 1024;
pub(super) const MAX_AUTHORITY_TRIES: usize = 6;
pub(super) const REFRESH_MIN_SECONDS: u64 = 15 * 60;
pub(super) const REFRESH_DEFAULT_INTERVAL: u64 = 60 * 60;

/*
 * directory service manages tor network state: consensus, relay descriptors,
 * and microdescriptors. provides path selection for circuit building.
 */
pub struct DirectoryService {
    pub(super) authorities: RwLock<Vec<DirectoryAuthority>>,
    pub(super) current_consensus: RwLock<Option<NetworkConsensus>>,
    pub(super) relay_descriptors: RwLock<BTreeMap<[u8; 20], RelayDescriptor>>,
    pub(super) microdescriptors: RwLock<BTreeMap<[u8; 32], Vec<u8>>>,
    pub(super) consensus_cache: Mutex<BTreeMap<String, Vec<u8>>>,
    pub(super) directory_stats: DirectoryStats,
    pub(super) last_consensus_fetch: AtomicU64,
    pub(super) consensus_fetch_interval: u64,
}

impl DirectoryService {
    pub fn new() -> Self {
        DirectoryService {
            authorities: RwLock::new(default_authorities()),
            current_consensus: RwLock::new(None),
            relay_descriptors: RwLock::new(BTreeMap::new()),
            microdescriptors: RwLock::new(BTreeMap::new()),
            consensus_cache: Mutex::new(BTreeMap::new()),
            directory_stats: DirectoryStats::default(),
            last_consensus_fetch: AtomicU64::new(0),
            consensus_fetch_interval: REFRESH_DEFAULT_INTERVAL,
        }
    }

    pub fn init(&self) -> Result<(), OnionError> {
        crate::log::info!("directory: init");
        self.fetch_consensus()?;
        self.ensure_microdescs()?;
        Ok(())
    }

    pub fn refresh(&self) -> Result<(), OnionError> {
        self.fetch_consensus()?;
        self.ensure_microdescs()?;
        Ok(())
    }

    pub fn get_stats(&self) -> &DirectoryStats {
        &self.directory_stats
    }

    pub fn fetch_interval(&self) -> u64 {
        self.consensus_fetch_interval
    }

    pub fn has_cached_consensus(&self, key: &str) -> bool {
        self.consensus_cache.lock().contains_key(key)
    }

    pub fn get_cached_consensus(&self, key: &str) -> Option<Vec<u8>> {
        self.consensus_cache.lock().get(key).cloned()
    }

    pub fn cache_consensus(&self, key: String, data: Vec<u8>) {
        self.consensus_cache.lock().insert(key, data);
    }

    pub fn clear_consensus_cache(&self) {
        self.consensus_cache.lock().clear();
    }

    pub(super) fn secure_random_u64(&self) -> u64 {
        vault::random_u64()
    }

    pub(super) fn jitter(&self, max: u64) -> u64 {
        self.secure_random_u64() % max
    }
}
