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

use super::find_state::{CURRENT_MATCH, MATCH_COUNT};
use core::sync::atomic::Ordering;

pub fn get_current_match_index() -> usize {
    CURRENT_MATCH.load(Ordering::Relaxed)
}

pub fn get_match_info() -> (usize, usize) {
    let count = MATCH_COUNT.load(Ordering::Relaxed);
    let current = if count > 0 { CURRENT_MATCH.load(Ordering::Relaxed) + 1 } else { 0 };
    (current, count)
}

pub fn format_match_info(buf: &mut [u8]) -> usize {
    let (current, total) = get_match_info();
    if total == 0 {
        buf[..10].copy_from_slice(b"No results");
        return 10;
    }
    let mut idx = 0;
    idx += format_num(&mut buf[idx..], current);
    buf[idx] = b'/';
    idx += 1;
    idx += format_num(&mut buf[idx..], total);
    idx
}

fn format_num(buf: &mut [u8], num: usize) -> usize {
    if num == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut n = num;
    let mut digits = [0u8; 6];
    let mut count = 0;
    while n > 0 && count < 6 {
        digits[count] = b'0' + (n % 10) as u8;
        n /= 10;
        count += 1;
    }
    for i in 0..count {
        buf[i] = digits[count - 1 - i];
    }
    count
}
