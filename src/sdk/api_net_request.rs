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

use super::app::{AppError, AppResult};
use crate::network::tcp;
use alloc::vec::Vec;

pub(super) fn send_request(req: &[u8], host: &str) -> AppResult<Vec<u8>> {
    let port = if host.contains(":443") { 443u16 } else { 80u16 };
    let host_clean = host.split(':').next().unwrap_or(host);
    let handle = tcp::connect_to(host_clean, port, 5000).map_err(|_| AppError::NetworkError)?;
    tcp::send_socket(handle, req).map_err(|_| AppError::NetworkError)?;
    let resp = tcp::recv_all(handle, 5000).map_err(|_| AppError::NetworkError)?;
    tcp::close_socket(handle);
    Ok(extract_body(&resp))
}

fn extract_body(resp: &[u8]) -> Vec<u8> {
    for i in 0..resp.len().saturating_sub(3) {
        if &resp[i..i + 4] == b"\r\n\r\n" {
            return resp[i + 4..].to_vec();
        }
    }
    resp.to_vec()
}
