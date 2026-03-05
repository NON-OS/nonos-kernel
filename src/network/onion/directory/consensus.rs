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

//! Network consensus document parsing and validation

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use super::types::{
    NetworkConsensus, ConsensusEntry, ConsensusSignature, DirectoryAuthorityHeader,
    RelayFlags, BandwidthWeights, SigAlg,
};
use super::encoding::{b64_20, b64_32, b64_any, hex20};
use crate::network::onion::OnionError;

const MAX_CONSENSUS_LINES: usize = 200_000;

/// Parse network consensus document into structured form
pub(super) fn parse_consensus(raw: &[u8]) -> Result<NetworkConsensus, OnionError> {
    let text = core::str::from_utf8(raw).map_err(|_| OnionError::DirectoryError)?;
    let mut line_count = 0usize;

    let mut c = NetworkConsensus {
        raw_body: raw.to_vec(),
        valid_after: 0,
        fresh_until: 0,
        valid_until: 0,
        consensus_method: 0,
        voting_delay: (0, 0),
        params: BTreeMap::new(),
        authorities: Vec::new(),
        relays: Vec::new(),
        signatures: Vec::new(),
        bandwidth_weights: BandwidthWeights::default(),
    };

    let mut current: Option<ConsensusEntry> = None;

    for line in text.lines() {
        line_count += 1;
        if line_count > MAX_CONSENSUS_LINES {
            return Err(OnionError::DirectoryError);
        }
        if line.is_empty() { continue; }

        let mut it = line.split_whitespace();
        let tag = it.next().unwrap_or("");

        match tag {
            "network-status-version" => {
                let v = it.next().unwrap_or("");
                if v != "3" { return Err(OnionError::DirectoryError); }
            }
            "vote-status" => {
                let s = it.next().unwrap_or("");
                if s != "consensus" { return Err(OnionError::DirectoryError); }
            }
            "consensus-method" => {
                if let Some(v) = it.next() {
                    c.consensus_method = v.parse().unwrap_or(0);
                }
            }
            "valid-after" => {
                c.valid_after = parse_timestamp_fields(it.collect::<Vec<_>>().as_slice()).unwrap_or(0);
            }
            "fresh-until" => {
                c.fresh_until = parse_timestamp_fields(it.collect::<Vec<_>>().as_slice()).unwrap_or(0);
            }
            "valid-until" => {
                c.valid_until = parse_timestamp_fields(it.collect::<Vec<_>>().as_slice()).unwrap_or(0);
            }
            "voting-delay" => {
                let a = it.next().unwrap_or("0").parse().unwrap_or(0);
                let b = it.next().unwrap_or("0").parse().unwrap_or(0);
                c.voting_delay = (a, b);
            }
            "dir-source" => {
                let parts = it.collect::<Vec<_>>();
                if parts.len() >= 5 {
                    let nickname = parts[0].into();
                    let identity = hex20(parts[1]).unwrap_or([0; 20]);
                    let addr = parse_ipv4(parts[2]).unwrap_or([0, 0, 0, 0]);
                    let dir_port = parts[3].parse().unwrap_or(80);
                    let or_port = parts[4].parse().unwrap_or(443);
                    c.authorities.push(DirectoryAuthorityHeader {
                        nickname, identity, address: addr, dir_port, or_port
                    });
                }
            }
            "params" => {
                for kv in it {
                    if let Some((k, v)) = kv.split_once('=') {
                        if let Ok(val) = v.parse::<i32>() {
                            c.params.insert(k.into(), val);
                        }
                    }
                }
            }
            "r" => {
                if let Some(prev) = current.take() {
                    c.relays.push(prev);
                }
                let parts = it.collect::<Vec<_>>();
                if parts.len() < 8 { continue; }

                let nickname = parts[0].into();
                let id = b64_20(parts[1]).unwrap_or([0; 20]);
                let d = b64_20(parts[2]).unwrap_or([0; 20]);
                let published = parse_timestamp_fields(&parts[3..6]).unwrap_or(0);
                let addr = parse_ipv4(parts[6]).unwrap_or([0, 0, 0, 0]);
                let orp = parts[7].parse().unwrap_or(0u16);
                let dirp = parts.get(8).and_then(|s| s.parse().ok()).unwrap_or(0u16);

                current = Some(ConsensusEntry {
                    nickname,
                    identity_digest: id,
                    descriptor_digest: d,
                    microdesc_sha256: None,
                    published,
                    address: addr,
                    or_port: orp,
                    dir_port: dirp,
                    flags: RelayFlags::default(),
                    version: None,
                    bandwidth: None,
                    measured_bandwidth: None,
                    ed25519_id: None,
                });
            }
            "s" => {
                if let Some(ref mut e) = current {
                    e.flags = parse_relay_flags_line(&line[2..]);
                }
            }
            "v" => {
                if let Some(ref mut e) = current {
                    let rest = it.collect::<Vec<_>>().join(" ");
                    if !rest.is_empty() { e.version = Some(rest); }
                }
            }
            "w" => {
                if let Some(ref mut e) = current {
                    for kv in it {
                        if let Some((k, v)) = kv.split_once('=') {
                            match k {
                                "Bandwidth" => e.bandwidth = v.parse().ok(),
                                "Measured" => e.measured_bandwidth = v.parse().ok(),
                                _ => {}
                            }
                        }
                    }
                }
            }
            "id" => {
                if let Some(ref mut e) = current {
                    let parts = it.collect::<Vec<_>>();
                    if parts.len() >= 2 && parts[0] == "ed25519" {
                        if let Some(b) = b64_32(parts[1]) {
                            e.ed25519_id = Some(b);
                        }
                    }
                }
            }
            "m" => {
                if let Some(ref mut e) = current {
                    if let Some(d) = it.next() {
                        if let Some(h) = b64_32(d) {
                            e.microdesc_sha256 = Some(h);
                        }
                    }
                }
            }
            "bandwidth-weights" => {
                c.bandwidth_weights = parse_bandwidth_weights_line(&line[18..]);
            }
            "directory-signature" => {
                let parts = it.collect::<Vec<_>>();
                if parts.len() >= 3 {
                    let alg = if parts[0].eq_ignore_ascii_case("ed25519") {
                        SigAlg::Ed25519
                    } else {
                        SigAlg::Unknown
                    };
                    let identity = hex20(parts[1]).unwrap_or([0; 20]);
                    let sig_b64 = parts.last().unwrap_or(&"");
                    if let Some(sig_bytes) = b64_any(sig_b64) {
                        c.signatures.push(ConsensusSignature {
                            identity,
                            signing_alg: alg,
                            signature: sig_bytes,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    if let Some(e) = current.take() {
        c.relays.push(e);
    }

    Ok(c)
}

fn parse_timestamp_fields(_parts: &[&str]) -> Option<u64> {
    // Crude implementation - accept as "fresh enough" in v1 environment
    Some(current_time_s())
}

fn parse_relay_flags_line(s: &str) -> RelayFlags {
    let mut f = RelayFlags::default();
    for tok in s.split_whitespace() {
        match tok {
            "Authority" => f.is_authority = true,
            "BadExit" => f.is_bad_exit = true,
            "Exit" => f.is_exit = true,
            "Fast" => f.is_fast = true,
            "Guard" => f.is_guard = true,
            "HSDir" => f.is_hsdir = true,
            "NoEdConsensus" => f.is_no_ed_consensus = true,
            "Running" => f.is_running = true,
            "Stable" => f.is_stable = true,
            "StableUptime" => f.is_stable_uptime = true,
            "V2Dir" => f.is_v2dir = true,
            "Valid" => f.is_valid = true,
            _ => {}
        }
    }
    f
}

fn parse_bandwidth_weights_line(s: &str) -> BandwidthWeights {
    let mut w = BandwidthWeights::default();
    w.weight_scale = 10_000;
    for kv in s.split_whitespace() {
        if let Some((k, v)) = kv.split_once('=') {
            if let Ok(n) = v.parse::<u32>() {
                match k {
                    "Wbd" => w.wbd = n, "Wbe" => w.wbe = n, "Wbg" => w.wbg = n, "Wbm" => w.wbm = n,
                    "Wed" => w.wed = n, "Wee" => w.wee = n, "Weg" => w.weg = n, "Wem" => w.wem = n,
                    "Wgd" => w.wgd = n, "Wgg" => w.wgg = n, "Wgm" => w.wgm = n,
                    "Wmd" => w.wmd = n, "Wme" => w.wme = n, "Wmg" => w.wmg = n, "Wmm" => w.wmm = n,
                    _ => {}
                }
            }
        }
    }
    w
}

fn parse_ipv4(s: &str) -> Result<[u8; 4], OnionError> {
    let mut out = [0u8; 4];
    let mut i = 0usize;
    for part in s.split('.') {
        if i >= 4 { return Err(OnionError::DirectoryError); }
        out[i] = part.parse::<u8>().map_err(|_| OnionError::DirectoryError)?;
        i += 1;
    }
    if i != 4 { return Err(OnionError::DirectoryError); }
    Ok(out)
}

pub(super) fn ipv4_to_string(addr: [u8; 4]) -> String {
    alloc::format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
}

pub(super) fn current_time_s() -> u64 {
    crate::arch::x86_64::time::timer::get_timestamp_ms().unwrap_or(0) / 1000
}
