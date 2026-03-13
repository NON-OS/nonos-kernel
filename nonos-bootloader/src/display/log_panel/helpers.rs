// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub(super) fn copy_prefix(buf: &mut [u8], prefix: &[u8]) -> usize {
    let len = prefix.len().min(buf.len());
    buf[..len].copy_from_slice(&prefix[..len]);
    len
}

pub(super) fn format_decimal(buf: &mut [u8], value: usize) -> usize {
    if value == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
            return 1;
        }
        return 0;
    }

    let mut num_buf = [0u8; 12];
    let mut num_pos = 0;
    let mut n = value;

    while n > 0 && num_pos < 12 {
        num_buf[num_pos] = b'0' + (n % 10) as u8;
        n /= 10;
        num_pos += 1;
    }

    let mut written = 0;
    for i in (0..num_pos).rev() {
        if written < buf.len() {
            buf[written] = num_buf[i];
            written += 1;
        }
    }
    written
}
