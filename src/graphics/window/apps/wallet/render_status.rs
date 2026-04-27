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

use super::render::{COLOR_BORDER, COLOR_GREEN, COLOR_RED, COLOR_TEXT_DIM, COLOR_TEXT_WHITE};
use super::state::{CACHED_BLOCK, STATUS_LEN, STATUS_MSG, STATUS_SUCCESS};
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::window::draw_string;
use core::sync::atomic::Ordering;

pub(super) fn draw_status_bar(x: u32, y: u32, w: u32) {
    for gy in 0..32u32 {
        let s = 28 - (gy / 4) as u8;
        fill_rect(
            x,
            y + gy,
            w,
            1,
            0xFF000000 | ((s as u32) << 16) | ((s as u32) << 8) | (s as u32),
        );
    }
    fill_rect(x, y, w, 1, COLOR_BORDER);
    let status = STATUS_MSG.lock();
    let status_len = STATUS_LEN.load(Ordering::SeqCst);
    let success = STATUS_SUCCESS.load(Ordering::SeqCst);
    if status_len > 0 {
        let color = if success { COLOR_GREEN } else { COLOR_RED };
        fill_rect(x + 16, y + 10, 8, 8, color);
        draw_string(x + 30, y + 9, &status[..status_len], COLOR_TEXT_WHITE);
    }
    let block_num = CACHED_BLOCK.load(Ordering::Relaxed);
    if block_num > 0 {
        let mut block_str = [0u8; 24];
        block_str[0] = b'B';
        block_str[1] = b'l';
        block_str[2] = b'o';
        block_str[3] = b'c';
        block_str[4] = b'k';
        block_str[5] = b':';
        block_str[6] = b' ';
        let len = format_u64(&mut block_str[7..], block_num);
        draw_string(x + w - 150, y + 9, &block_str[..7 + len], COLOR_TEXT_DIM);
    }
}

fn format_u64(buf: &mut [u8], n: u64) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut val = n;
    let mut digits = [0u8; 20];
    let mut dc = 0;
    while val > 0 {
        digits[dc] = (val % 10) as u8;
        val /= 10;
        dc += 1;
    }
    for i in (0..dc).rev() {
        buf[dc - 1 - i] = b'0' + digits[i];
    }
    dc
}
