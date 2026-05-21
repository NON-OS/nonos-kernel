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

use super::constants::*;
use crate::clients::envelope::call;

pub fn set_gateway(port: u32, ip: [u8; 4], gw_port: u16) -> Result<(), u16> {
    let mut body = [0u8; 7];
    body[0..4].copy_from_slice(&ip);
    body[4..6].copy_from_slice(&gw_port.to_le_bytes());
    body[6] = 1;
    call(port, MAGIC, SET_GATEWAY, &body, &mut []).map(|_| ())
}

pub fn set_authority(port: u32, authority: &[u8; 32]) -> Result<(), u16> {
    call(port, MAGIC, SET_AUTHORITY, authority, &mut []).map(|_| ())
}

pub fn set_topology(port: u32, topology: &[u8]) -> Result<(), u16> {
    call(port, MAGIC, SET_TOPOLOGY, topology, &mut []).map(|_| ())
}

pub fn set_credential(port: u32, credential: &[u8]) -> Result<(), u16> {
    call(port, MAGIC, SET_CREDENTIAL, credential, &mut []).map(|_| ())
}

pub fn set_timing(port: u32, cover_burst: u16, jitter_ms: u16) -> Result<(), u16> {
    let mut body = [0u8; 4];
    body[0..2].copy_from_slice(&cover_burst.to_le_bytes());
    body[2..4].copy_from_slice(&jitter_ms.to_le_bytes());
    call(port, MAGIC, SET_TIMING, &body, &mut []).map(|_| ())
}
