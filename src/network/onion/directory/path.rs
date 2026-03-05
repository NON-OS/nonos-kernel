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

//! Path selection algorithms for circuit building

use super::types::{BandwidthWeights, ConsensusEntry};

/// Extract /16 network prefix from IPv4 address
pub(super) fn ipv4_net16(a: [u8; 4]) -> u16 {
    ((a[0] as u16) << 8) | (a[1] as u16)
}

/// Check if two relays are in the same family
pub(super) fn family_conflict(a: &ConsensusEntry, b: &ConsensusEntry) -> bool {
    // Check ed25519 identity equality as "same node" guard
    if let (Some(x), Some(y)) = (a.ed25519_id, b.ed25519_id) {
        if x == y { return true; }
    }
    false
}

/// Check if two addresses are in the same /16 subnet
pub(super) fn subnet16_conflict(a: [u8; 4], b: [u8; 4]) -> bool {
    ipv4_net16(a) == ipv4_net16(b)
}

/// Select a relay from candidates using bandwidth-weighted random selection
pub(super) fn weighted_pick<'a>(
    v: &'a [&'a ConsensusEntry],
    w: &BandwidthWeights,
    pos: &str,
    rnd: u64,
) -> &'a ConsensusEntry {
    let total: u128 = v.iter().map(|e| relay_weight(e, w, pos) as u128).sum();

    if total == 0 {
        return v[rnd as usize % v.len()];
    }

    let mut point = (rnd as u128) % total;
    for e in v {
        let weight = relay_weight(e, w, pos) as u128;
        if point < weight {
            return e;
        }
        point -= weight;
    }

    v[0]
}

/// Calculate weight for a relay based on position in circuit
pub(super) fn relay_weight(e: &ConsensusEntry, w: &BandwidthWeights, pos: &str) -> u64 {
    let bw = e.measured_bandwidth.or(e.bandwidth).unwrap_or(1000) as u64;
    let mult = match pos {
        "guard" => w.wgg as u64,
        "middle" => w.wmm as u64,
        "exit" => w.wee as u64,
        _ => w.weight_scale as u64,
    };
    (bw * mult) / w.weight_scale.max(1) as u64
}
