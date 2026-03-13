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
use core::sync::atomic::{AtomicPtr, Ordering};
use uefi::prelude::*;
use uefi::table::boot::BootServices;
use uefi::Identify;

use super::logger::LogLevel;

static BOOT_SERVICES: AtomicPtr<BootServices> = AtomicPtr::new(core::ptr::null_mut());

pub fn init_logger(st: &mut SystemTable<Boot>) {
    let bs_ptr = st.boot_services() as *const BootServices as *mut BootServices;
    BOOT_SERVICES.store(bs_ptr, Ordering::Release);
}

fn level_to_str(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Debug => "DEBUG",
        LogLevel::Info => "INFO",
        LogLevel::Warn => "WARN",
        LogLevel::Error => "ERROR",
        LogLevel::Critical => "CRIT",
    }
}

pub(super) fn write_log_global(level: LogLevel, category: &str, message: &str) {
    let bs_ptr = BOOT_SERVICES.load(Ordering::Acquire);
    if bs_ptr.is_null() {
        return;
    }

    let log_line = format!("[{}] {}: {}\r\n", level_to_str(level), category, message);

    unsafe {
        let bs = &*bs_ptr;
        if let Ok(handles) = bs.locate_handle_buffer(uefi::table::boot::SearchType::ByProtocol(
            &uefi::proto::console::text::Output::GUID,
        )) {
            if let Some(&handle) = handles.first() {
                if let Ok(mut output) =
                    bs.open_protocol_exclusive::<uefi::proto::console::text::Output>(handle)
                {
                    let mut buf = [0u16; 512];
                    let mut idx = 0;
                    for c in log_line.chars() {
                        if idx >= buf.len() - 1 {
                            break;
                        }
                        buf[idx] = c as u16;
                        idx += 1;
                    }
                    buf[idx] = 0;

                    if let Ok(s) = uefi::CStr16::from_u16_with_nul(&buf[..=idx]) {
                        let _ = output.output_string(s);
                    }
                }
            }
        }
    }
}

pub(super) fn write_log(st: &mut SystemTable<Boot>, level: LogLevel, category: &str, message: &str) {
    let log_line = format!("[{}] {}: {}\r\n", level_to_str(level), category, message);

    let mut buf = [0u16; 512];
    let mut idx = 0;
    for c in log_line.chars() {
        if idx >= buf.len() - 1 {
            break;
        }
        buf[idx] = c as u16;
        idx += 1;
    }
    buf[idx] = 0;

    if let Ok(s) = uefi::CStr16::from_u16_with_nul(&buf[..=idx]) {
        let _ = st.stdout().output_string(s);
    }
}
