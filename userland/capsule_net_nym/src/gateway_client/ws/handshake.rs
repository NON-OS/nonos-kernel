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

use alloc::vec::Vec;

use super::{accept, base64, request};
use crate::crypto::fill_random;
use crate::state::Gateway;
use crate::tcp_client;

pub fn handshake(tcp_port: u32, gateway: Gateway) -> Result<(), u16> {
    let mut raw_key = [0u8; 16];
    fill_random(&mut raw_key).map_err(|_| 9u16)?;
    let mut key = [0u8; 24];
    let Some(key_len) = base64::encode(&raw_key, &mut key) else { return Err(9) };
    let req = request::build(gateway.ip, gateway.port, core::str::from_utf8(&key[..key_len]).map_err(|_| 9u16)?);
    tcp_client::send_all(tcp_port, gateway.stream, req.as_bytes())?;
    let resp = read_headers(tcp_port, gateway.stream)?;
    if !accept::verify(&resp, &key[..key_len]) {
        return Err(9);
    }
    Ok(())
}

fn read_headers(tcp_port: u32, stream: u32) -> Result<Vec<u8>, u16> {
    let mut resp = Vec::with_capacity(2048);
    let mut chunk = [0u8; 512];
    for _ in 0..16 {
        let n = tcp_client::recv(tcp_port, stream, &mut chunk)?;
        if n == 0 {
            continue;
        }
        resp.extend_from_slice(&chunk[..n]);
        if resp.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(resp);
        }
        if resp.len() > 2048 {
            return Err(9);
        }
    }
    Err(9)
}
