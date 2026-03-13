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

use core::sync::atomic::Ordering;
use uefi::prelude::*;
use uefi::proto::console::gop::GraphicsOutput;
use uefi::Identify;

use super::state::{FB_FORMAT_BGR, FB_HEIGHT, FB_INITIALIZED, FB_PTR, FB_STRIDE, FB_WIDTH};

pub fn init_gop(st: &mut SystemTable<Boot>) -> bool {
    let bs = st.boot_services();

    let handles = match bs.locate_handle_buffer(
        uefi::table::boot::SearchType::ByProtocol(&GraphicsOutput::GUID),
    ) {
        Ok(h) => h,
        Err(_) => {
            if let Ok(gop_handle) = bs.get_handle_for_protocol::<GraphicsOutput>() {
                return try_init_gop_handle(bs, gop_handle);
            }
            return false;
        }
    };

    for &handle in handles.iter() {
        if try_init_gop_handle(bs, handle) {
            return true;
        }
    }

    false
}

fn try_init_gop_handle(bs: &uefi::table::boot::BootServices, gop_handle: Handle) -> bool {
    let gop = match bs.open_protocol_exclusive::<GraphicsOutput>(gop_handle) {
        Ok(g) => g,
        Err(_) => return false,
    };

    let mode_info = gop.current_mode_info();
    let (width, height) = mode_info.resolution();

    if width == 0 || height == 0 {
        return false;
    }

    let stride = mode_info.stride();
    let mut gop = gop;
    let mut frame_buffer = gop.frame_buffer();
    let fb_addr = frame_buffer.as_mut_ptr() as u64;

    if fb_addr == 0 {
        return false;
    }

    let is_bgr = matches!(
        mode_info.pixel_format(),
        uefi::proto::console::gop::PixelFormat::Bgr
    );

    FB_PTR.store(fb_addr, Ordering::SeqCst);
    FB_WIDTH.store(width as u32, Ordering::SeqCst);
    FB_HEIGHT.store(height as u32, Ordering::SeqCst);
    FB_STRIDE.store(stride as u32, Ordering::SeqCst);
    FB_FORMAT_BGR.store(is_bgr, Ordering::SeqCst);
    FB_INITIALIZED.store(true, Ordering::SeqCst);

    true
}
