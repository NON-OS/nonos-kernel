// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::state::*;
use crate::display::framebuffer::dimensions;
use core::sync::atomic::Ordering;

const DIALOG_W: u32 = 420;
const DIALOG_H: u32 = 200;
const INPUT_DIALOG_H: u32 = 240;

pub(crate) fn handle_click(mx: i32, my: i32) -> bool {
    if !is_active() {
        return false;
    }
    let (sw, sh) = dimensions();
    let dtype = DIALOG_TYPE.load(Ordering::Relaxed);
    let h = if dtype == DIALOG_INPUT { INPUT_DIALOG_H } else { DIALOG_H };
    let x = ((sw - DIALOG_W) / 2) as i32;
    let y = ((sh - h) / 2) as i32;
    let btn_y = y + h as i32 - 52;

    match dtype {
        DIALOG_INPUT => {
            let create_x = x + DIALOG_W as i32 / 2 - 100;
            if mx >= create_x && mx < create_x + 90 && my >= btn_y && my < btn_y + 36 {
                DIALOG_RESULT.store(RESULT_OK, Ordering::Relaxed);
                return true;
            }
            let cancel_x = x + DIALOG_W as i32 / 2 + 10;
            if mx >= cancel_x && mx < cancel_x + 90 && my >= btn_y && my < btn_y + 36 {
                DIALOG_RESULT.store(RESULT_CANCEL, Ordering::Relaxed);
                return true;
            }
        }
        DIALOG_CONFIRM => {
            let yes_x = x + DIALOG_W as i32 / 2 - 100;
            if mx >= yes_x && mx < yes_x + 90 && my >= btn_y && my < btn_y + 36 {
                DIALOG_RESULT.store(RESULT_YES, Ordering::Relaxed);
                DIALOG_ACTIVE.store(false, Ordering::Relaxed);
                return true;
            }
            let no_x = x + DIALOG_W as i32 / 2 + 10;
            if mx >= no_x && mx < no_x + 90 && my >= btn_y && my < btn_y + 36 {
                DIALOG_RESULT.store(RESULT_NO, Ordering::Relaxed);
                DIALOG_ACTIVE.store(false, Ordering::Relaxed);
                return true;
            }
        }
        _ => {
            let ok_x = x + DIALOG_W as i32 / 2 - 45;
            if mx >= ok_x && mx < ok_x + 90 && my >= btn_y && my < btn_y + 36 {
                DIALOG_RESULT.store(RESULT_OK, Ordering::Relaxed);
                DIALOG_ACTIVE.store(false, Ordering::Relaxed);
                return true;
            }
        }
    }
    mx >= x && mx < x + DIALOG_W as i32 && my >= y && my < y + h as i32
}

pub(crate) fn handle_key(ch: u8) -> bool {
    if !is_input_dialog() {
        return false;
    }

    match ch {
        0x08 | 0x7F => {
            input_pop_char();
            true
        }
        0x0D | 0x0A => {
            DIALOG_RESULT.store(RESULT_OK, Ordering::Relaxed);
            true
        }
        0x1B => {
            DIALOG_RESULT.store(RESULT_CANCEL, Ordering::Relaxed);
            true
        }
        ch if ch >= 0x20 && ch < 0x7F => {
            input_push_char(ch);
            true
        }
        _ => false,
    }
}
