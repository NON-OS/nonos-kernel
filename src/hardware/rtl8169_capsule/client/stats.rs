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

use super::super::capability::gate_call;
use super::super::error::DriverRtl8169Error;
use super::super::protocol::{encode_request, OP_STATS, STATS_PAYLOAD_LEN};
use super::seq::next_request_id;
use super::status_map::lift;
use super::transport::round_trip;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rtl8169Stats {
    pub cmd: u32,
    pub phy_status: u32,
    pub isr: u32,
    pub imr: u32,
    pub rx_config: u32,
    pub tx_config: u32,
    pub rms: u32,
    pub rx_cur: u32,
    pub tx_cur: u32,
    pub rx_desc_count: u32,
    pub tx_desc_count: u32,
}

pub fn stats() -> Result<Rtl8169Stats, DriverRtl8169Error> {
    let _caller = gate_call()?;
    let request_id = next_request_id();
    let frame = encode_request(OP_STATS, 0, request_id, &[]);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(lift(resp.status));
    }
    decode_stats(&resp.body)
}

fn decode_stats(body: &[u8]) -> Result<Rtl8169Stats, DriverRtl8169Error> {
    if body.len() < STATS_PAYLOAD_LEN {
        return Err(DriverRtl8169Error::ProtocolMismatch);
    }
    Ok(Rtl8169Stats {
        cmd: read_u32(body, 0),
        phy_status: read_u32(body, 4),
        isr: read_u32(body, 8),
        imr: read_u32(body, 12),
        rx_config: read_u32(body, 16),
        tx_config: read_u32(body, 20),
        rms: read_u32(body, 24),
        rx_cur: read_u32(body, 28),
        tx_cur: read_u32(body, 32),
        rx_desc_count: read_u32(body, 36),
        tx_desc_count: read_u32(body, 40),
    })
}

fn read_u32(body: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]])
}
