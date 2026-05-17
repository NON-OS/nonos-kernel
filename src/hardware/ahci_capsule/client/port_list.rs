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

use alloc::vec::Vec;

use super::super::capability::gate_call;
use super::super::error::DriverAhciError;
use super::super::protocol::{
    encode_request, MAX_PORTS, OP_PORT_LIST, PORT_ENTRY_BYTES, PORT_LIST_HEADER_BYTES,
};
use super::seq::next_request_id;
use super::status_map::lift;
use super::transport::round_trip;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AhciPortInfo {
    pub index: u8,
    pub implemented: u8,
    pub present: u8,
    pub kind: u8,
    pub ssts: u32,
    pub sig: u32,
    pub interrupt_status: u32,
    pub command_status: u32,
    pub task_file_data: u32,
    pub sata_error: u32,
    pub active_commands: u32,
    pub issued_commands: u32,
}

pub fn port_list() -> Result<Vec<AhciPortInfo>, DriverAhciError> {
    let _caller = gate_call()?;
    let request_id = next_request_id();
    let frame = encode_request(OP_PORT_LIST, 0, request_id, &[]);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(lift(resp.status));
    }
    decode_ports(&resp.body)
}

fn decode_ports(body: &[u8]) -> Result<Vec<AhciPortInfo>, DriverAhciError> {
    if body.len() < PORT_LIST_HEADER_BYTES {
        return Err(DriverAhciError::ProtocolMismatch);
    }
    let count = core::cmp::min(read_u32(body, 0) as usize, MAX_PORTS);
    let need = PORT_LIST_HEADER_BYTES + count * PORT_ENTRY_BYTES;
    if body.len() < need {
        return Err(DriverAhciError::ProtocolMismatch);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        out.push(decode_port(body, PORT_LIST_HEADER_BYTES + i * PORT_ENTRY_BYTES));
    }
    Ok(out)
}

fn decode_port(body: &[u8], off: usize) -> AhciPortInfo {
    AhciPortInfo {
        index: body[off],
        implemented: body[off + 1],
        present: body[off + 2],
        kind: body[off + 3],
        ssts: read_u32(body, off + 4),
        sig: read_u32(body, off + 8),
        interrupt_status: read_u32(body, off + 12),
        command_status: read_u32(body, off + 16),
        task_file_data: read_u32(body, off + 20),
        sata_error: read_u32(body, off + 24),
        active_commands: read_u32(body, off + 28),
        issued_commands: read_u32(body, off + 32),
    }
}

fn read_u32(body: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]])
}
