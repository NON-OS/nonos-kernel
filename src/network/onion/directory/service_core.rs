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
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, RwLock};

use super::authorities::default_authorities;
use super::consensus::current_time_s;
use super::types::{
    DirectoryAuthority, DirectoryStats, NetworkConsensus, RelayDescriptor, SigAlg,
};
use crate::crypto::{sig, vault};
use crate::network::onion::OnionError;

const REFRESH_DEFAULT_INTERVAL: u64 = 60 * 60;

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

    pub(super) fn validate_consensus(&self, c: &mut NetworkConsensus) -> Result<(), OnionError> {
        let now = current_time_s();

        if now < c.valid_after || now > c.valid_until {
            return Err(OnionError::DirectoryError);
        }

        let auths = self.authorities.read();
        let mut id_to_ed: BTreeMap<[u8; 20], [u8; 32]> = BTreeMap::new();

        for a in auths.iter() {
            if let Some(ed) = a.ed25519_identity {
                if let Some(h) = c.authorities.iter().find(|h| h.nickname == a.nickname) {
                    id_to_ed.insert(h.identity, ed);
                }
            }
        }

        let mut good = 0usize;
        for s in &c.signatures {
            if s.signing_alg != SigAlg::Ed25519 { continue; }
            let Some(pk) = id_to_ed.get(&s.identity).copied() else { continue; };
            if sig::ed25519_verify(&pk, &c.raw_body, &s.signature).unwrap_or(false) {
                good += 1;
            }
        }

        if good < 3 { return Err(OnionError::DirectoryError); }
        Ok(())
    }

    pub(super) fn update_relay_statistics(&self) {
        if let Some(c) = self.current_consensus.read().as_ref() {
            let total = c.relays.len() as u32;
            let guards = c.relays.iter().filter(|r| r.flags.is_guard).count() as u32;
            let exits = c.relays.iter().filter(|r| r.flags.is_exit).count() as u32;

            self.directory_stats.relay_count.store(total, Ordering::Relaxed);
            self.directory_stats.guard_count.store(guards, Ordering::Relaxed);
            self.directory_stats.exit_count.store(exits, Ordering::Relaxed);

            let age = current_time_s().saturating_sub(c.valid_after);
            self.directory_stats.last_consensus_age.store(age, Ordering::Relaxed);
        }
    }

    pub(super) fn secure_random_u64(&self) -> u64 {
        vault::random_u64()
    }

    pub(super) fn jitter(&self, max: u64) -> u64 {
        self.secure_random_u64() % max
    }
}
