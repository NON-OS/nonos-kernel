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
use super::{collector, CapsuleStats, GlobalStats};
use crate::capsule::CapsuleId;
use alloc::vec::Vec;

pub fn export_capsule(id: CapsuleId) -> Option<Vec<u8>> {
    let s = collector::get(id)?;
    Some(encode_stats(&s))
}

pub fn export_global() -> Vec<u8> {
    let g = collector::global();
    encode_global(&g)
}

fn encode_stats(s: &CapsuleStats) -> Vec<u8> {
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(&s.cpu_ns.to_le_bytes());
    out.extend_from_slice(&s.mem_peak.to_le_bytes());
    out.extend_from_slice(&s.mem_current.to_le_bytes());
    out.extend_from_slice(&s.syscalls.to_le_bytes());
    out.extend_from_slice(&s.ipc_sent.to_le_bytes());
    out.extend_from_slice(&s.ipc_recv.to_le_bytes());
    out.extend_from_slice(&s.net_tx.to_le_bytes());
    out.extend_from_slice(&s.net_rx.to_le_bytes());
    out.extend_from_slice(&s.started_at.to_le_bytes());
    out.extend_from_slice(&s.duration_ns.to_le_bytes());
    out
}

fn encode_global(g: &GlobalStats) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(&g.active_capsules.to_le_bytes());
    out.extend_from_slice(&g.total_launched.to_le_bytes());
    out.extend_from_slice(&g.total_exited.to_le_bytes());
    out.extend_from_slice(&g.total_faulted.to_le_bytes());
    out.extend_from_slice(&g.total_cpu_ns.to_le_bytes());
    out.extend_from_slice(&g.total_mem_used.to_le_bytes());
    out
}

pub fn decode_stats(data: &[u8]) -> Option<CapsuleStats> {
    if data.len() < 80 {
        return None;
    }
    Some(CapsuleStats {
        cpu_ns: u64::from_le_bytes(data[0..8].try_into().ok()?),
        mem_peak: u64::from_le_bytes(data[8..16].try_into().ok()?),
        mem_current: u64::from_le_bytes(data[16..24].try_into().ok()?),
        syscalls: u64::from_le_bytes(data[24..32].try_into().ok()?),
        ipc_sent: u64::from_le_bytes(data[32..40].try_into().ok()?),
        ipc_recv: u64::from_le_bytes(data[40..48].try_into().ok()?),
        net_tx: u64::from_le_bytes(data[48..56].try_into().ok()?),
        net_rx: u64::from_le_bytes(data[56..64].try_into().ok()?),
        started_at: u64::from_le_bytes(data[64..72].try_into().ok()?),
        duration_ns: u64::from_le_bytes(data[72..80].try_into().ok()?),
    })
}
