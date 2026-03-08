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
use crate::network::onion::OnionError;

/*
 * parses http response with body size cap to prevent memory exhaustion.
 * returns status code and body bytes.
 */
pub(crate) fn parse_http_response_bounded(resp: &[u8], cap: usize) -> Result<(u16, Vec<u8>), OnionError> {
    if resp.len() < 12 { return Err(OnionError::DirectoryError); }
    let text = core::str::from_utf8(resp).map_err(|_| OnionError::DirectoryError)?;

    let header_end = text.find("\r\n\r\n").ok_or(OnionError::DirectoryError)?;
    let (head, body) = text.split_at(header_end + 4);

    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut sl = status_line.split_whitespace();
    let _http = sl.next().unwrap_or("");
    let code = sl.next().unwrap_or("0").parse::<u16>().unwrap_or(0);

    let mut content_length: Option<usize> = None;
    for h in lines {
        if h.is_empty() { continue; }
        let (k, v) = match h.split_once(':') { Some(x) => x, None => continue };
        if k.eq_ignore_ascii_case("content-length") {
            if let Ok(n) = v.trim().parse::<usize>() {
                content_length = Some(n);
            }
        }
    }

    let mut body_bytes = body.as_bytes().to_vec();
    if let Some(n) = content_length {
        if n > cap { return Err(OnionError::DirectoryError); }
        if n <= body_bytes.len() {
            body_bytes.truncate(n);
        }
    }
    if body_bytes.len() > cap { return Err(OnionError::DirectoryError); }
    Ok((code, body_bytes))
}
