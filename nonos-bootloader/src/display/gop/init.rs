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
    match bs.locate_handle_buffer(uefi::table::boot::SearchType::ByProtocol(&GraphicsOutput::GUID)) {
        Ok(h) => { for &hnd in h.iter() { if try_init(bs, hnd) { return true; } } false }
        Err(_) => bs.get_handle_for_protocol::<GraphicsOutput>().map(|h| try_init(bs, h)).unwrap_or(false),
    }
}

fn try_init(bs: &uefi::table::boot::BootServices, h: Handle) -> bool {
    let mut gop = match bs.open_protocol_exclusive::<GraphicsOutput>(h) { Ok(g) => g, Err(_) => return false };
    let info = gop.current_mode_info();
    let (w, ht) = info.resolution();
    if w == 0 || ht == 0 { return false; }
    let fb_addr = gop.frame_buffer().as_mut_ptr() as u64;
    if fb_addr == 0 { return false; }
    let bgr = matches!(info.pixel_format(), uefi::proto::console::gop::PixelFormat::Bgr);
    FB_PTR.store(fb_addr, Ordering::SeqCst);
    FB_WIDTH.store(w as u32, Ordering::SeqCst);
    FB_HEIGHT.store(ht as u32, Ordering::SeqCst);
    FB_STRIDE.store(info.stride() as u32, Ordering::SeqCst);
    FB_FORMAT_BGR.store(bgr, Ordering::SeqCst);
    FB_INITIALIZED.store(true, Ordering::SeqCst);
    true
}
