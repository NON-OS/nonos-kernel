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

extern crate alloc;

use alloc::format;
use uefi::prelude::*;
use uefi::Identify;

use crate::log::buffer::{utf8_to_utf16, Utf16Buffer};
use crate::log::global::{get_boot_services, increment_log_count, is_initialized};
use crate::log::types::LogLevel;
/// Write a log line to UEFI console using SystemTable
pub fn write_log_st(st: &mut SystemTable<Boot>, level: LogLevel, category: &str, message: &str) {
    let log_line = format!("[{}] {}: {}\r\n", level.as_str(), category, message);
    let mut buf = [0u16; 512];
    let len = utf8_to_utf16(&log_line, &mut buf);
    if let Ok(s) = uefi::CStr16::from_u16_with_nul(&buf[..len]) {
        let _ = st.stdout().output_string(s);
    }

    increment_log_count();
}

/// Write a log line to UEFI console using global state
pub fn write_log_global(level: LogLevel, category: &str, message: &str) {
    if !is_initialized() {
        return;
    }

    let bs_ptr = get_boot_services();
    if bs_ptr.is_null() {
        return;
    }

    let log_line = format!("[{}] {}: {}\r\n", level.as_str(), category, message);
    // ## SAFETY: Boot Services pointer is valid while logger is initialized
    unsafe {
        let bs = &*bs_ptr;
        write_to_console_via_bs(bs, &log_line);
    }

    increment_log_count();
}

/// Write directly to console via Boot Services protocol lookup
unsafe fn write_to_console_via_bs(bs: &BootServices, message: &str) {
    // Locate Simple Text Output Protocol
    let search =
        uefi::table::boot::SearchType::ByProtocol(&uefi::proto::console::text::Output::GUID);

    if let Ok(handles) = bs.locate_handle_buffer(search) {
        if let Some(&handle) = handles.first() {
            if let Ok(mut output) =
                bs.open_protocol_exclusive::<uefi::proto::console::text::Output>(handle)
            {
                let mut buf = [0u16; 512];
                let len = utf8_to_utf16(message, &mut buf);

                if let Ok(s) = uefi::CStr16::from_u16_with_nul(&buf[..len]) {
                    let _ = output.output_string(s);
                }
            }
        }
    }
}

pub fn write_raw_st(st: &mut SystemTable<Boot>, message: &uefi::CStr16) {
    let _ = st.stdout().output_string(message);
}

pub fn write_buffer_st(st: &mut SystemTable<Boot>, buf: &Utf16Buffer) {
    if let Some(s) = buf.as_cstr16() {
        let _ = st.stdout().output_string(s);
    }
}

pub fn write_newline_st(st: &mut SystemTable<Boot>) {
    let _ = st.stdout().output_string(cstr16!("\r\n"));
}

pub fn clear_console_st(st: &mut SystemTable<Boot>) {
    let _ = st.stdout().clear();
}

pub fn set_cursor_st(st: &mut SystemTable<Boot>, col: usize, row: usize) {
    let _ = st.stdout().set_cursor_position(col, row);
}

pub fn set_cursor_visible_st(st: &mut SystemTable<Boot>, visible: bool) {
    let _ = st.stdout().enable_cursor(visible);
}
