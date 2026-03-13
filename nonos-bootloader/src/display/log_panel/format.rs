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

/*
 * Log formatting utilities.
 *
 * Format hex values, hashes, memory ranges, and numbers for display.
 */

use super::api::log;
use super::helpers::{copy_prefix, format_decimal};
use super::types::LogLevel;

const HEX: &[u8] = b"0123456789abcdef";

pub fn log_hex(prefix: &[u8], value: u64) {
    let mut buf = [0u8; 58];
    let mut pos = copy_prefix(&mut buf, prefix);

    if pos + 18 <= buf.len() {
        buf[pos] = b'0';
        buf[pos + 1] = b'x';
        pos += 2;

        for i in (0..16).rev() {
            buf[pos] = HEX[((value >> (i * 4)) & 0xF) as usize];
            pos += 1;
        }
    }

    log(LogLevel::Ok, &buf[..pos]);
}

pub fn log_hash(prefix: &[u8], hash: &[u8]) {
    let mut buf = [0u8; 58];
    let mut pos = copy_prefix(&mut buf, prefix);

    for &byte in hash.iter().take(16) {
        if pos + 2 <= buf.len() {
            buf[pos] = HEX[(byte >> 4) as usize];
            buf[pos + 1] = HEX[(byte & 0xF) as usize];
            pos += 2;
        }
    }

    log(LogLevel::Ok, &buf[..pos]);

    if hash.len() > 16 {
        let mut buf2 = [0u8; 58];
        buf2[0..6].copy_from_slice(b"      ");
        let mut pos2 = 6;

        for &byte in hash.iter().skip(16) {
            if pos2 + 2 <= buf2.len() {
                buf2[pos2] = HEX[(byte >> 4) as usize];
                buf2[pos2 + 1] = HEX[(byte & 0xF) as usize];
                pos2 += 2;
            }
        }
        log(LogLevel::Info, &buf2[..pos2]);
    }
}

pub fn log_hash_full(label: &[u8], hash: &[u8]) {
    log(LogLevel::Ok, label);

    let mut buf = [0u8; 58];
    buf[0..4].copy_from_slice(b"  0x");
    let mut pos = 4;

    for &byte in hash {
        if pos + 2 <= buf.len() {
            buf[pos] = HEX[(byte >> 4) as usize];
            buf[pos + 1] = HEX[(byte & 0xF) as usize];
            pos += 2;
        }
    }
    log(LogLevel::Info, &buf[..pos]);
}

pub fn log_mem(start: u64, end: u64, kind: &[u8]) {
    let mut buf = [0u8; 58];
    let mut pos = 0;

    buf[pos..pos + 2].copy_from_slice(b"0x");
    pos += 2;

    for i in (0..12).rev() {
        buf[pos] = HEX[((start >> (i * 4)) & 0xF) as usize];
        pos += 1;
    }

    buf[pos..pos + 3].copy_from_slice(b"-0x");
    pos += 3;

    for i in (0..12).rev() {
        buf[pos] = HEX[((end >> (i * 4)) & 0xF) as usize];
        pos += 1;
    }

    buf[pos] = b' ';
    pos += 1;

    let klen = kind.len().min(buf.len() - pos);
    buf[pos..pos + klen].copy_from_slice(&kind[..klen]);
    pos += klen;

    log(LogLevel::Info, &buf[..pos]);
}

pub fn log_size(prefix: &[u8], size: usize) {
    let mut buf = [0u8; 58];
    let mut pos = copy_prefix(&mut buf, prefix);

    pos += format_decimal(&mut buf[pos..], size);

    if pos + 6 <= buf.len() {
        buf[pos..pos + 6].copy_from_slice(b" bytes");
        pos += 6;
    }

    log(LogLevel::Ok, &buf[..pos]);
}

pub fn log_u32(prefix: &[u8], value: u32) {
    let mut buf = [0u8; 58];
    let mut pos = copy_prefix(&mut buf, prefix);
    pos += format_decimal(&mut buf[pos..], value as usize);
    log(LogLevel::Info, &buf[..pos]);
}

