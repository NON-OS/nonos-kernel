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
use uefi::Identify;

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

/*
 * issue #8 fix: on optimus laptops (acer nitro, asus rog, msi with nvidia+intel),
 * the first GOP handle is often the discrete nvidia gpu which has no display
 * connected. we need to try ALL handles and find the one with a valid framebuffer.
 *
 * signs of wrong adapter: width=0, height=0, or fb_addr=0
 * the intel igpu will have the actual panel connected and valid fb.
 */
pub fn get_framebuffer_info(bs: &BootServices) -> FramebufferInfo {
    /* try to enumerate all GOP handles first */
    if let Ok(handles) = bs.locate_handle_buffer(uefi::table::boot::SearchType::ByProtocol(&GraphicsOutput::GUID)) {
        log_info("handoff", &format!("Found {} GOP adapters", handles.len()));

        for (idx, &handle) in handles.iter().enumerate() {
            if let Some(fb_info) = try_gop_handle(bs, handle, idx) {
                return fb_info;
            }
        }
    }

    /* fallback to single handle method if enumerate fails */
    if let Ok(gop_handle) = bs.get_handle_for_protocol::<GraphicsOutput>() {
        if let Some(fb_info) = try_gop_handle(bs, gop_handle, 0) {
            return fb_info;
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

fn try_gop_handle(bs: &BootServices, handle: Handle, idx: usize) -> Option<FramebufferInfo> {
    let mut gop = match bs.open_protocol_exclusive::<GraphicsOutput>(handle) {
        Ok(g) => g,
        Err(_) => return None,
    };

    let mode_info = gop.current_mode_info();
    let (width, height) = mode_info.resolution();

    /* skip adapters with bogus resolution - nvidia dgpu returns 0x0 when no display */
    if width == 0 || height == 0 {
        log_info("handoff", &format!("GOP[{}]: skipping ({}x{} invalid)", idx, width, height));
        return None;
    }

    let stride = mode_info.stride();
    let mut frame_buffer = gop.frame_buffer();
    let fb_addr = frame_buffer.as_mut_ptr() as u64;

    /* skip if framebuffer address is null */
    if fb_addr == 0 {
        log_info("handoff", &format!("GOP[{}]: skipping (null fb)", idx));
        return None;
    }

    let fb_size = frame_buffer.size() as u64;

    let pixel_format = match mode_info.pixel_format() {
        uefi::proto::console::gop::PixelFormat::Bgr => 1,
        uefi::proto::console::gop::PixelFormat::Rgb => 0,
        _ => 2,
    };

    log_info(
        "handoff",
        &format!("GOP[{}]: using {}x{} stride={} @ {:016X}", idx, width, height, stride, fb_addr),
    );

    Some(FramebufferInfo {
        ptr: fb_addr,
        size: fb_size,
        width: width as u32,
        height: height as u32,
        stride: stride as u32,
        pixel_format,
    })
}
