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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_WHITE, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_ACCENT, COLOR_RED};

pub(super) fn print_addr(prefix: &[u8], addr: &[u8; 42]) {
    let mut line = [0u8; 64];
    let plen = prefix.len().min(20);
    line[..plen].copy_from_slice(&prefix[..plen]);
    line[plen..plen + 42].copy_from_slice(addr);
    print_line(&line[..plen + 42], COLOR_TEXT);
}

pub(super) fn print_count(prefix: &[u8], count: usize) {
    let mut line = [0u8; 16];
    let plen = prefix.len().min(12);
    line[..plen].copy_from_slice(&prefix[..plen]);
    line[plen] = b'0' + (count % 10) as u8;
    print_line(&line[..plen + 1], COLOR_TEXT_DIM);
}

pub(super) fn print_account(i: usize, addr: &[u8; 42], active: bool) {
    let mut line = [0u8; 52];
    line[0] = b'[';
    line[1] = b'0' + (i % 10) as u8;
    line[2] = b']';
    line[3] = b' ';
    if active {
        line[4..7].copy_from_slice(b">> ");
    } else {
        line[4..7].copy_from_slice(b"   ");
    }
    line[7..49].copy_from_slice(addr);
    print_line(&line[..49], if active { COLOR_GREEN } else { COLOR_TEXT });
}

pub(super) fn print_stealth(enc: &[u8; 140]) {
    let mut l1 = [0u8; 72];
    l1[..2].copy_from_slice(b"  ");
    l1[2..72].copy_from_slice(&enc[..70]);
    print_line(&l1, COLOR_TEXT_WHITE);

    let mut l2 = [0u8; 72];
    l2[..2].copy_from_slice(b"  ");
    l2[2..72].copy_from_slice(&enc[70..140]);
    print_line(&l2, COLOR_TEXT_WHITE);
}

pub(super) fn print_balance(eth: u64, wei: u64) {
    let dec = wei / 1_000_000_000_000_000;
    let mut line = [0u8; 32];
    line[..10].copy_from_slice(b"Balance:  ");
    let mut pos = 10;

    if eth == 0 {
        line[pos] = b'0';
        pos += 1;
    } else {
        let mut n = eth;
        let mut digits = [0u8; 20];
        let mut dpos = 0;
        while n > 0 {
            digits[dpos] = (n % 10) as u8;
            n /= 10;
            dpos += 1;
        }
        for i in (0..dpos).rev() {
            line[pos] = b'0' + digits[i];
            pos += 1;
        }
    }

    line[pos] = b'.';
    pos += 1;
    line[pos] = b'0' + ((dec / 100) % 10) as u8;
    pos += 1;
    line[pos] = b'0' + ((dec / 10) % 10) as u8;
    pos += 1;
    line[pos] = b'0' + (dec % 10) as u8;
    pos += 1;

    print_line(&line[..pos], COLOR_TEXT);
    print_line(b"  NOX", COLOR_ACCENT);
}

pub(super) fn print_err(e: &str) {
    let b = e.as_bytes();
    let len = b.len().min(60);
    let mut line = [0u8; 64];
    line[..len].copy_from_slice(&b[..len]);
    print_line(&line[..len], COLOR_RED);
}

pub(super) fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0xFF,
    }
}
