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

use super::constants::*;
use super::io::{inw, outw};

#[inline]
pub fn vbe_write(index: u16, value: u16) {
    outw(VBE_INDEX_PORT, index);
    outw(VBE_DATA_PORT, value);
}

#[inline]
pub fn vbe_read(index: u16) -> u16 {
    outw(VBE_INDEX_PORT, index);
    inw(VBE_DATA_PORT)
}

pub fn vbe_detect() -> bool {
    vbe_read(VBE_DISPI_INDEX_ID) == VBE_DISPI_ID_MAGIC
}

pub fn vbe_disable() {
    vbe_write(VBE_DISPI_INDEX_ENABLE, 0);
}

pub fn vbe_enable_lfb() {
    vbe_write(
        VBE_DISPI_INDEX_ENABLE,
        VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED | VBE_DISPI_NOCLEARMEM,
    );
}

pub fn vbe_enable_lfb_clear() {
    vbe_write(
        VBE_DISPI_INDEX_ENABLE,
        VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED,
    );
}

pub fn program_mode(width: u16, height: u16, bpp: u16) -> u32 {
    vbe_disable();
    vbe_write(VBE_DISPI_INDEX_XRES, width);
    vbe_write(VBE_DISPI_INDEX_YRES, height);
    vbe_write(VBE_DISPI_INDEX_BPP, bpp);
    vbe_write(VBE_DISPI_INDEX_VIRT_WIDTH, width);
    vbe_write(VBE_DISPI_INDEX_VIRT_HEIGHT, height);
    vbe_write(VBE_DISPI_INDEX_X_OFFSET, 0);
    vbe_write(VBE_DISPI_INDEX_Y_OFFSET, 0);
    vbe_enable_lfb();

    (width as u32) * (bpp as u32 / 8)
}

pub fn get_current_mode() -> (u16, u16, u16) {
    let width = vbe_read(VBE_DISPI_INDEX_XRES);
    let height = vbe_read(VBE_DISPI_INDEX_YRES);
    let bpp = vbe_read(VBE_DISPI_INDEX_BPP);
    (width, height, bpp)
}

pub fn set_panning_offset(x: u16, y: u16) {
    vbe_write(VBE_DISPI_INDEX_X_OFFSET, x);
    vbe_write(VBE_DISPI_INDEX_Y_OFFSET, y);
}

pub fn set_virtual_size(width: u16, height: u16) {
    vbe_write(VBE_DISPI_INDEX_VIRT_WIDTH, width);
    vbe_write(VBE_DISPI_INDEX_VIRT_HEIGHT, height);
}

pub fn validate_mode(fb_size: usize, width: u16, height: u16, bpp: u16) -> Result<u32, &'static str> {
    if bpp != 32 {
        return Err("Only 32bpp is supported");
    }

    let pitch = width as u32 * (bpp as u32 / 8);
    let needed = pitch as usize * height as usize;
    if needed > fb_size {
        return Err("Requested mode exceeds framebuffer size");
    }

    Ok(pitch)
}
