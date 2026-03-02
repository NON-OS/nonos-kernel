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
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_YELLOW, COLOR_ACCENT};
use crate::shell::commands::utils::format_num_simple;

pub fn cmd_dmesg() {
    cmd_dmesg_with_args(&[]);
}

pub fn cmd_dmesg_with_args(args: &[&[u8]]) {
    let mut clear = false;
    let mut count: Option<usize> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == b"-c" || arg == b"--clear" {
            clear = true;
        } else if arg == b"-n" || arg == b"--lines" {
            if i + 1 < args.len() {
                i += 1;
                count = parse_usize(args[i]);
            }
        } else if arg.starts_with(b"-n") && arg.len() > 2 {
            count = parse_usize(&arg[2..]);
        }
        i += 1;
    }

    print_line(b"Kernel Messages:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);

    let entries = match count {
        Some(n) => crate::log::get_recent_logs(n),
        None => crate::log::get_log_entries(),
    };

    if entries.is_empty() {
        print_line(b"(no kernel messages)", COLOR_TEXT_DIM);
    } else {
        for entry in &entries {
            let mut line = [0u8; 320];
            let len = format_log_entry(&mut line, entry);
            let color = severity_color(entry.sev);
            print_line(&line[..len], color);
        }

        print_line(b"", COLOR_TEXT);
        let mut count_line = [0u8; 48];
        count_line[..1].copy_from_slice(b"(");
        let num_len = format_num_simple(&mut count_line[1..], entries.len());
        let suffix = b" entries shown)";
        count_line[1+num_len..1+num_len+suffix.len()].copy_from_slice(suffix);
        print_line(&count_line[..1+num_len+suffix.len()], COLOR_TEXT_DIM);
    }

    if clear {
        crate::log::clear_log_buffer();
        print_line(b"(kernel ring buffer cleared)", COLOR_TEXT_DIM);
    }
}

fn format_log_entry(buf: &mut [u8], entry: &crate::log::LogEntry) -> usize {
    let mut pos = 0;

    buf[pos] = b'[';
    pos += 1;

    let tsc_per_sec = 2_000_000_000u64;
    let seconds = entry.ts / tsc_per_sec;
    let millis = ((entry.ts % tsc_per_sec) * 1000) / tsc_per_sec;

    pos += format_timestamp(&mut buf[pos..], seconds, millis as u32);

    buf[pos] = b']';
    pos += 1;

    buf[pos..pos+4].copy_from_slice(b"[CPU");
    pos += 4;
    pos += format_num_simple(&mut buf[pos..], entry.cpu as usize);
    buf[pos] = b']';
    pos += 1;

    buf[pos] = b'[';
    pos += 1;
    let sev_str = entry.sev.as_str().as_bytes();
    let pad_len = 5 - sev_str.len();
    for _ in 0..pad_len {
        buf[pos] = b' ';
        pos += 1;
    }
    buf[pos..pos+sev_str.len()].copy_from_slice(sev_str);
    pos += sev_str.len();
    buf[pos] = b']';
    pos += 1;

    buf[pos] = b' ';
    pos += 1;

    let msg_bytes = entry.msg.as_bytes();
    let msg_len = msg_bytes.len().min(buf.len() - pos);
    buf[pos..pos+msg_len].copy_from_slice(&msg_bytes[..msg_len]);
    pos += msg_len;

    pos
}

fn format_timestamp(buf: &mut [u8], seconds: u64, millis: u32) -> usize {
    let mut pos = 0;

    if seconds < 10 {
        buf[pos..pos+4].copy_from_slice(b"    ");
        pos += 4;
    } else if seconds < 100 {
        buf[pos..pos+3].copy_from_slice(b"   ");
        pos += 3;
    } else if seconds < 1000 {
        buf[pos..pos+2].copy_from_slice(b"  ");
        pos += 2;
    } else if seconds < 10000 {
        buf[pos] = b' ';
        pos += 1;
    }

    pos += format_num_simple(&mut buf[pos..], seconds as usize);

    buf[pos] = b'.';
    pos += 1;

    let ms = millis.min(999);
    buf[pos] = b'0' + ((ms / 100) as u8);
    pos += 1;
    buf[pos] = b'0' + (((ms / 10) % 10) as u8);
    pos += 1;
    buf[pos] = b'0' + ((ms % 10) as u8);
    pos += 1;

    pos
}

fn severity_color(sev: crate::log::Severity) -> u32 {
    match sev {
        crate::log::Severity::Debug => COLOR_TEXT_DIM,
        crate::log::Severity::Info => COLOR_TEXT,
        crate::log::Severity::Warn => COLOR_YELLOW,
        crate::log::Severity::Err => COLOR_ACCENT,
        crate::log::Severity::Fatal => COLOR_ACCENT,
    }
}

fn parse_usize(s: &[u8]) -> Option<usize> {
    if s.is_empty() {
        return None;
    }
    let mut result: usize = 0;
    for &b in s {
        if b < b'0' || b > b'9' {
            return None;
        }
        result = result.checked_mul(10)?.checked_add((b - b'0') as usize)?;
    }
    Some(result)
}
