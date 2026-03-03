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


use core::cmp::min;
use crate::network::{get_network_stack, tcp::TcpSocket};
use crate::network::onion::OnionError;

pub(super) fn write_all(sock: &TcpSocket, data: &[u8], timeout_ms: u64) -> Result<(), OnionError> {
    let start = crate::time::timestamp_millis();
    if let Some(net) = get_network_stack() {
        let mut off = 0usize;
        while off < data.len() {
            if crate::time::timestamp_millis().saturating_sub(start) > timeout_ms {
                return Err(OnionError::Timeout);
            }
            match net.tcp_send(sock.connection_id(), &data[off..]) {
                Ok(n) if n > 0 => off += n,
                Ok(_) => crate::time::yield_now(),
                Err(_) => return Err(OnionError::NetworkError),
            }
        }
        Ok(())
    } else {
        Err(OnionError::NetworkError)
    }
}

pub(super) fn read_some(sock: &TcpSocket, dst: &mut [u8], timeout_ms: u64) -> Result<usize, OnionError> {
    let start = crate::time::timestamp_millis();
    if let Some(net) = get_network_stack() {
        loop {
            if crate::time::timestamp_millis().saturating_sub(start) > timeout_ms {
                return Err(OnionError::Timeout);
            }
            match net.tcp_receive(sock.connection_id(), dst.len()) {
                Ok(buf) if !buf.is_empty() => {
                    let n = min(dst.len(), buf.len());
                    dst[..n].copy_from_slice(&buf[..n]);
                    return Ok(n);
                }
                _ => crate::time::yield_now(),
            }
        }
    } else {
        Err(OnionError::NetworkError)
    }
}
