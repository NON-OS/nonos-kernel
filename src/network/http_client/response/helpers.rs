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

pub(crate) fn find_sequence(data: &[u8], seq: &[u8]) -> Option<usize> {
    data.windows(seq.len()).position(|w| w == seq)
}

pub(super) fn parse_status_code(data: &[u8]) -> Result<u16, &'static str> {
    if data.len() < 3 {
        return Err("invalid status code");
    }
    let mut code: u16 = 0;
    for &b in data.iter().take(3) {
        if !b.is_ascii_digit() {
            return Err("invalid status code");
        }
        code = code * 10 + (b - b'0') as u16;
    }
    Ok(code)
}

pub(super) fn trim_crlf(line: &[u8]) -> &[u8] {
    if line.ends_with(b"\r") {
        &line[..line.len() - 1]
    } else {
        line
    }
}
