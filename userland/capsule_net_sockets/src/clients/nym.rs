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

use alloc::vec;

use super::envelope::call;

const MAGIC: u32 = 0x4E59_4D31;
const SET_GATEWAY: u16 = 2;
const OPEN: u16 = 3;
const SEND: u16 = 4;
const RECV: u16 = 5;
const CLOSE: u16 = 7;

pub fn set_gateway(port: u32, ip: [u8; 4], gw_port: u16) -> Result<(), u16> {
    let mut body = [0u8; 6];
    body[0..4].copy_from_slice(&ip);
    body[4..6].copy_from_slice(&gw_port.to_le_bytes());
    call(port, MAGIC, SET_GATEWAY, &body, &mut []).map(|_| ())
}

pub fn open(port: u32) -> Result<u32, u16> {
    let mut out = [0u8; 4];
    call(port, MAGIC, OPEN, &[], &mut out)?;
    Ok(u32::from_le_bytes(out))
}

pub fn send(port: u32, session: u32, payload: &[u8]) -> Result<(), u16> {
    let mut body = vec![0u8; 4 + payload.len()];
    body[0..4].copy_from_slice(&session.to_le_bytes());
    body[4..].copy_from_slice(payload);
    call(port, MAGIC, SEND, &body, &mut []).map(|_| ())
}

pub fn recv(port: u32, session: u32, out: &mut [u8]) -> Result<usize, u16> {
    call(port, MAGIC, RECV, &session.to_le_bytes(), out)
}

pub fn close(port: u32, session: u32) -> Result<(), u16> {
    call(port, MAGIC, CLOSE, &session.to_le_bytes(), &mut []).map(|_| ())
}
