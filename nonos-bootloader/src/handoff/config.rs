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
use uefi::proto::console::gop::GraphicsOutput;
use uefi::table::boot::BootServices;
use uefi::table::cfg::{ACPI2_GUID, ACPI_GUID, SMBIOS3_GUID, SMBIOS_GUID};

use super::types::FramebufferInfo;
use crate::log::logger::{log_info, log_warn};

pub fn get_acpi_rsdp(st: &SystemTable<Boot>) -> u64 {
    for entry in st.config_table() {
        if entry.guid == ACPI2_GUID {
            log_info(
                "handoff",
                &format!("Found ACPI 2.0 RSDP at {:p}", entry.address),
            );
            return entry.address as u64;
        }
    }
    for entry in st.config_table() {
        if entry.guid == ACPI_GUID {
            log_info(
                "handoff",
                &format!("Found ACPI 1.0 RSDP at {:p}", entry.address),
            );
            return entry.address as u64;
        }
    }
    log_warn("handoff", "ACPI RSDP not found");
    0
}

pub fn get_smbios_entry(st: &SystemTable<Boot>) -> u64 {
    for entry in st.config_table() {
        if entry.guid == SMBIOS3_GUID {
            log_info(
                "handoff",
                &format!("Found SMBIOS 3.0 at {:p}", entry.address),
            );
            return entry.address as u64;
        }
    }
    for entry in st.config_table() {
        if entry.guid == SMBIOS_GUID {
            log_info(
                "handoff",
                &format!("Found SMBIOS 2.x at {:p}", entry.address),
            );
            return entry.address as u64;
        }
    }
    log_warn("handoff", "SMBIOS not found");
    0
}

pub fn get_framebuffer_info(bs: &BootServices) -> FramebufferInfo {
    if let Ok(gop_handle) = bs.get_handle_for_protocol::<GraphicsOutput>() {
        if let Ok(mut gop) = bs.open_protocol_exclusive::<GraphicsOutput>(gop_handle) {
            let mode_info = gop.current_mode_info();
            let (width, height) = mode_info.resolution();
            let stride = mode_info.stride();

            let mut frame_buffer = gop.frame_buffer();
            let fb_addr = frame_buffer.as_mut_ptr() as u64;
            let fb_size = frame_buffer.size() as u64;

            let pixel_format = match mode_info.pixel_format() {
                uefi::proto::console::gop::PixelFormat::Bgr => 1,
                uefi::proto::console::gop::PixelFormat::Rgb => 0,
                _ => 2,
            };

            log_info(
                "handoff",
                &format!("GOP framebuffer: {}x{} @ {:016X}", width, height, fb_addr),
            );

            return FramebufferInfo {
                ptr: fb_addr,
                size: fb_size,
                width: width as u32,
                height: height as u32,
                stride: stride as u32,
                pixel_format,
            };
        }
    }

    log_warn("handoff", "GOP not available, no framebuffer");
    FramebufferInfo {
        ptr: 0,
        size: 0,
        width: 0,
        height: 0,
        stride: 0,
        pixel_format: 0,
    }
}
