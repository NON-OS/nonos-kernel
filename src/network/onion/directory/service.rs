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

//! Directory service implementation for fetching and managing Tor network state

use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use core::cmp::min;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, RwLock};

use super::types::{
    DirectoryAuthority, DirectoryStats, NetworkConsensus, RelayDescriptor, SigAlg,
};
use super::authorities::default_authorities;
use super::consensus::{current_time_s, ipv4_to_string, parse_consensus};
use super::encoding::b64_url_nopad;
use super::microdesc::{max_microdesc_size, parse_microdesc, sha256_of_text, split_microdesc_blobs};
use super::path::{family_conflict, subnet16_conflict, weighted_pick};
use crate::crypto::{sig, vault};
use crate::network::get_network_stack;
use crate::network::onion::circuit::PathConstraints;
use crate::network::onion::OnionError;

const MAX_HTTP_BODY_BYTES: usize = 5 * 1024 * 1024;
const MAX_AUTHORITY_TRIES: usize = 6;
const REFRESH_MIN_SECONDS: u64 = 15 * 60;
const REFRESH_DEFAULT_INTERVAL: u64 = 60 * 60;

/// Complete directory service implementation
pub struct DirectoryService {
    authorities: RwLock<Vec<DirectoryAuthority>>,
    current_consensus: RwLock<Option<NetworkConsensus>>,
    relay_descriptors: RwLock<BTreeMap<[u8; 20], RelayDescriptor>>,
    microdescriptors: RwLock<BTreeMap<[u8; 32], Vec<u8>>>,
    consensus_cache: Mutex<BTreeMap<String, Vec<u8>>>,
    directory_stats: DirectoryStats,
    last_consensus_fetch: AtomicU64,
    consensus_fetch_interval: u64,
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

    pub fn fetch_consensus(&self) -> Result<(), OnionError> {
        let now = current_time_s();
        let last = self.last_consensus_fetch.load(Ordering::Relaxed);
        if now.saturating_sub(last) < REFRESH_MIN_SECONDS {
            return Ok(());
        }

        let auths = self.authorities.read();
        let mut attempt = 0usize;
        let mut last_err: Option<OnionError> = None;

        let offset = self.secure_random_u64() as usize % auths.len().max(1);
        while attempt < min(auths.len(), MAX_AUTHORITY_TRIES).max(1) {
            let a = &auths[(offset + attempt) % auths.len()];
            self.directory_stats.authorities_contacted.fetch_add(1, Ordering::Relaxed);

            match self.fetch_from_authority(a, "/tor/status-vote/current/consensus") {
                Ok(body) => {
                    match parse_consensus(&body) {
                        Ok(mut c) => {
                            if let Err(e) = self.validate_consensus(&mut c) {
                                self.directory_stats.consensus_parse_errors.fetch_add(1, Ordering::Relaxed);
                                last_err = Some(e);
                                attempt += 1;
                                continue;
                            }
                            self.directory_stats.consensus_fetches.fetch_add(1, Ordering::Relaxed);
                            *self.current_consensus.write() = Some(c);
                            self.last_consensus_fetch.store(now + self.jitter(5), Ordering::Relaxed);
                            self.update_relay_statistics();
                            return Ok(());
                        }
                        Err(e) => {
                            self.directory_stats.consensus_parse_errors.fetch_add(1, Ordering::Relaxed);
                            last_err = Some(e);
                        }
                    }
                }
                Err(e) => { last_err = Some(e); }
            }
            attempt += 1;
        }

        Err(last_err.unwrap_or(OnionError::DirectoryError))
    }

    fn ensure_microdescs(&self) -> Result<(), OnionError> {
        let c = self.current_consensus.read();
        let c = c.as_ref().ok_or(OnionError::DirectoryError)?;

        let mut need: Vec<[u8; 32]> = Vec::new();
        {
            let have = self.microdescriptors.read();
            for e in &c.relays {
                if let Some(d) = e.microdesc_sha256 {
                    if !have.contains_key(&d) {
                        need.push(d);
                    }
                }
            }
        }

        if need.is_empty() { return Ok(()); }

        let auths = self.authorities.read();
        let max_md_size = max_microdesc_size();

        for a in auths.iter() {
            let mut path = String::from("/tor/micro/d/");
            const MAX_PER_REQUEST: usize = 25;

            for chunk in need.chunks(MAX_PER_REQUEST) {
                path.truncate("/tor/micro/d/".len());
                for (i, d) in chunk.iter().enumerate() {
                    if i > 0 { path.push('+'); }
                    path.push_str(&b64_url_nopad(&d[..]));
                }

                if let Ok(body) = self.fetch_from_authority(a, &path) {
                    let texts = split_microdesc_blobs(&body);
                    for t in texts {
                        if t.len() > max_md_size { continue; }
                        if let Some(d) = sha256_of_text(&t) {
                            self.microdescriptors.write().insert(d, t);
                        }
                    }
                    self.directory_stats.descriptor_fetches.fetch_add(1, Ordering::Relaxed);
                }
            }
            break;
        }

        self.materialize_relays_from_microdescs()?;
        Ok(())
    }

    fn materialize_relays_from_microdescs(&self) -> Result<(), OnionError> {
        let c = self.current_consensus.read();
        let c = c.as_ref().ok_or(OnionError::DirectoryError)?;

        let micro = self.microdescriptors.read();
        let mut out = self.relay_descriptors.write();

        for e in &c.relays {
            let Some(md_sha) = e.microdesc_sha256 else { continue; };
            let Some(text) = micro.get(&md_sha) else { continue; };

            let parsed = parse_microdesc(text).unwrap_or_default();
            if parsed.ntor_key.len() != 32 { continue; }

            let mut ed = [0u8; 32];
            if let Some(x) = e.ed25519_id { ed = x; }

            let rd = RelayDescriptor {
                nickname: e.nickname.clone(),
                identity_digest: e.identity_digest,
                ed25519_identity: ed,
                ntor_onion_key: parsed.ntor_key.to_vec(),
                address: e.address,
                port: e.or_port,
                dir_port: e.dir_port,
                bandwidth: e.measured_bandwidth.unwrap_or(e.bandwidth.unwrap_or(0)),
                measured_bandwidth: e.measured_bandwidth.unwrap_or(0),
                flags: e.flags.clone(),
                fingerprint: e.identity_digest,
                family: parsed.family,
                country_code: String::new(),
                as_number: 0,
                consensus_weight: 0,
                guard_probability: 0.0,
                middle_probability: 0.0,
                exit_probability: 0.0,
                exit_ports: parsed.exit_ports,
            };

            out.insert(e.identity_digest, rd);
        }

        Ok(())
    }

    fn fetch_from_authority(&self, authority: &DirectoryAuthority, path: &str) -> Result<Vec<u8>, OnionError> {
        let Some(net) = get_network_stack() else { return Err(OnionError::NetworkError); };

        let req = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             User-Agent: NONOS/1.0\r\n\
             Accept: */*\r\n\
             Accept-Encoding: identity\r\n\
             Connection: close\r\n\r\n",
            path, ipv4_to_string(authority.address), authority.dir_port
        );

        let resp = net.http_request(authority.address, authority.dir_port, req.as_bytes())
            .map_err(|_| OnionError::NetworkError)?;

        let (status, body) = parse_http_response_bounded(&resp, MAX_HTTP_BODY_BYTES)?;
        if status / 100 != 2 { return Err(OnionError::DirectoryError); }
        Ok(body)
    }

    fn validate_consensus(&self, c: &mut NetworkConsensus) -> Result<(), OnionError> {
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

    pub fn select_path_with_constraints(&self, constraints: &PathConstraints) -> Result<Vec<RelayDescriptor>, OnionError> {
        let c = self.current_consensus.read();
        let c = c.as_ref().ok_or(OnionError::DirectoryError)?;

        let guards: Vec<_> = c.relays.iter()
            .filter(|r| r.flags.is_guard && r.flags.is_running && r.flags.is_valid)
            .filter(|r| r.bandwidth.unwrap_or(0) >= constraints.min_bandwidth)
            .collect();

        let middles: Vec<_> = c.relays.iter()
            .filter(|r| r.flags.is_running && r.flags.is_valid && !r.flags.is_authority)
            .filter(|r| r.bandwidth.unwrap_or(0) >= constraints.min_bandwidth)
            .collect();

        let exits: Vec<_> = c.relays.iter()
            .filter(|r| r.flags.is_exit && r.flags.is_running && r.flags.is_valid && !r.flags.is_bad_exit)
            .filter(|r| r.bandwidth.unwrap_or(0) >= constraints.min_bandwidth)
            .collect();

        if guards.is_empty() || middles.is_empty() || exits.is_empty() {
            return Err(OnionError::InsufficientRelays);
        }

        let gw = &c.bandwidth_weights;
        let guard = weighted_pick(&guards, gw, "guard", self.secure_random_u64());
        let mut middle = weighted_pick(&middles, gw, "middle", self.secure_random_u64());
        let mut exit = weighted_pick(&exits, gw, "exit", self.secure_random_u64());

        for _ in 0..8 {
            if !family_conflict(guard, middle) && !family_conflict(guard, exit)
                && !subnet16_conflict(guard.address, middle.address)
                && !subnet16_conflict(guard.address, exit.address)
                && !subnet16_conflict(middle.address, exit.address) {
                break;
            }
            middle = weighted_pick(&middles, gw, "middle", self.secure_random_u64());
            exit = weighted_pick(&exits, gw, "exit", self.secure_random_u64());
        }

        let mut path = Vec::new();
        for e in [guard, middle, exit] {
            let rds = self.relay_descriptors.read();
            if let Some(rd) = rds.get(&e.identity_digest) {
                path.push(rd.clone());
            } else {
                drop(rds);
                if let Some(d) = e.microdesc_sha256 {
                    self.fetch_microdesc_for_digest(&d)?;
                    self.materialize_relays_from_microdescs()?;
                    let rds2 = self.relay_descriptors.read();
                    if let Some(rd2) = rds2.get(&e.identity_digest) {
                        path.push(rd2.clone());
                    } else {
                        return Err(OnionError::DirectoryError);
                    }
                } else {
                    return Err(OnionError::DirectoryError);
                }
            }
        }

        Ok(path)
    }

    pub fn select_path(&self) -> Result<Vec<RelayDescriptor>, OnionError> {
        self.select_path_with_constraints(&PathConstraints::default())
    }

    /// Select a circuit path where the exit relay supports the required ports
    ///
    /// If `required_ports` is empty, selects any exit relay. Otherwise, only
    /// selects exit relays that explicitly support all specified ports.
    pub fn select_path_with_exit_policy(&self, required_ports: &[u16]) -> Result<Vec<RelayDescriptor>, OnionError> {
        let c = self.current_consensus.read();
        let c = c.as_ref().ok_or(OnionError::DirectoryError)?;

        // Get relay descriptors for exit policy checking
        let rds = self.relay_descriptors.read();

        // Select guards (same as normal path selection)
        let guards: Vec<_> = c.relays.iter()
            .filter(|r| r.flags.is_guard && r.flags.is_running && r.flags.is_valid)
            .collect();

        // Select middles (same as normal path selection)
        let middles: Vec<_> = c.relays.iter()
            .filter(|r| r.flags.is_running && r.flags.is_valid && !r.flags.is_authority)
            .collect();

        // Select exits that support the required ports
        let exits: Vec<_> = if required_ports.is_empty() {
            // Any exit relay is fine
            c.relays.iter()
                .filter(|r| r.flags.is_exit && r.flags.is_running && r.flags.is_valid && !r.flags.is_bad_exit)
                .collect()
        } else {
            // Filter to exits that support all required ports
            c.relays.iter()
                .filter(|r| {
                    if !r.flags.is_exit || !r.flags.is_running || !r.flags.is_valid || r.flags.is_bad_exit {
                        return false;
                    }
                    // Check if this relay's descriptor supports all required ports
                    if let Some(rd) = rds.get(&r.identity_digest) {
                        rd.allows_all_ports(required_ports)
                    } else {
                        // If we don't have the descriptor, assume it doesn't support
                        false
                    }
                })
                .collect()
        };

        drop(rds); // Release lock before further operations

        if guards.is_empty() || middles.is_empty() || exits.is_empty() {
            return Err(OnionError::InsufficientRelays);
        }

        let gw = &c.bandwidth_weights;
        let guard = weighted_pick(&guards, gw, "guard", self.secure_random_u64());
        let mut middle = weighted_pick(&middles, gw, "middle", self.secure_random_u64());
        let mut exit = weighted_pick(&exits, gw, "exit", self.secure_random_u64());

        // Avoid path conflicts (same as normal selection)
        for _ in 0..8 {
            if !family_conflict(guard, middle) && !family_conflict(guard, exit)
                && !subnet16_conflict(guard.address, middle.address)
                && !subnet16_conflict(guard.address, exit.address)
                && !subnet16_conflict(middle.address, exit.address) {
                break;
            }
            middle = weighted_pick(&middles, gw, "middle", self.secure_random_u64());
            exit = weighted_pick(&exits, gw, "exit", self.secure_random_u64());
        }

        let mut path = Vec::new();
        for e in [guard, middle, exit] {
            let rds = self.relay_descriptors.read();
            if let Some(rd) = rds.get(&e.identity_digest) {
                path.push(rd.clone());
            } else {
                drop(rds);
                if let Some(d) = e.microdesc_sha256 {
                    self.fetch_microdesc_for_digest(&d)?;
                    self.materialize_relays_from_microdescs()?;
                    let rds2 = self.relay_descriptors.read();
                    if let Some(rd2) = rds2.get(&e.identity_digest) {
                        path.push(rd2.clone());
                    } else {
                        return Err(OnionError::DirectoryError);
                    }
                } else {
                    return Err(OnionError::DirectoryError);
                }
            }
        }

        Ok(path)
    }

    pub fn get_stats(&self) -> &DirectoryStats {
        &self.directory_stats
    }

    fn fetch_microdesc_for_digest(&self, d: &[u8; 32]) -> Result<(), OnionError> {
        let auths = self.authorities.read();
        let max_md_size = max_microdesc_size();

        for a in auths.iter() {
            let path = {
                let mut s = String::from("/tor/micro/d/");
                s.push_str(&b64_url_nopad(&d[..]));
                s
            };

            if let Ok(body) = self.fetch_from_authority(a, &path) {
                let texts = split_microdesc_blobs(&body);
                for t in texts {
                    if t.len() > max_md_size { continue; }
                    if let Some(d2) = sha256_of_text(&t) {
                        if &d2 == d {
                            self.microdescriptors.write().insert(*d, t);
                            return Ok(());
                        }
                    }
                }
            }
        }
        Err(OnionError::DirectoryError)
    }

    fn update_relay_statistics(&self) {
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

    fn secure_random_u64(&self) -> u64 {
        vault::random_u64()
    }

    fn jitter(&self, max: u64) -> u64 {
        self.secure_random_u64() % max
    }

    /// Get the consensus fetch interval
    pub fn fetch_interval(&self) -> u64 {
        self.consensus_fetch_interval
    }

    /// Check if consensus cache contains a key
    pub fn has_cached_consensus(&self, key: &str) -> bool {
        self.consensus_cache.lock().contains_key(key)
    }

    /// Get cached consensus by key
    pub fn get_cached_consensus(&self, key: &str) -> Option<Vec<u8>> {
        self.consensus_cache.lock().get(key).cloned()
    }

    /// Store consensus in cache
    pub fn cache_consensus(&self, key: String, data: Vec<u8>) {
        self.consensus_cache.lock().insert(key, data);
    }

    /// Clear consensus cache
    pub fn clear_consensus_cache(&self) {
        self.consensus_cache.lock().clear();
    }
}

fn parse_http_response_bounded(resp: &[u8], cap: usize) -> Result<(u16, Vec<u8>), OnionError> {
    if resp.len() < 12 { return Err(OnionError::DirectoryError); }
    let text = core::str::from_utf8(resp).map_err(|_| OnionError::DirectoryError)?;

    let header_end = text.find("\r\n\r\n").ok_or(OnionError::DirectoryError)?;
    let (head, body) = text.split_at(header_end + 4);

    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut sl = status_line.split_whitespace();
    let _http = sl.next().unwrap_or("");
    let code = sl.next().unwrap_or("0").parse::<u16>().unwrap_or(0);

    let mut content_length: Option<usize> = None;
    for h in lines {
        if h.is_empty() { continue; }
        let (k, v) = match h.split_once(':') { Some(x) => x, None => continue };
        if k.eq_ignore_ascii_case("content-length") {
            if let Ok(n) = v.trim().parse::<usize>() {
                content_length = Some(n);
            }
        }
    }

    let mut body_bytes = body.as_bytes().to_vec();
    if let Some(n) = content_length {
        if n > cap { return Err(OnionError::DirectoryError); }
        if n <= body_bytes.len() {
            body_bytes.truncate(n);
        }
    }
    if body_bytes.len() > cap { return Err(OnionError::DirectoryError); }
    Ok((code, body_bytes))
}
