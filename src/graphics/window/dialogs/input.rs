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

use core::sync::atomic::Ordering;
use crate::graphics::framebuffer::dimensions;
use super::state::*;

const DIALOG_W: u32 = 400;
const DIALOG_H: u32 = 180;

pub(crate) fn handle_click(mx: i32, my: i32) -> bool {
    if !is_active() { return false; }
    let (sw, sh) = dimensions();
    let x = ((sw - DIALOG_W) / 2) as i32;
    let y = ((sh - DIALOG_H) / 2) as i32;
    let btn_y = y + DIALOG_H as i32 - 45;
    let dtype = DIALOG_TYPE.load(Ordering::Relaxed);

    match dtype {
        DIALOG_CONFIRM => {
            let yes_x = x + DIALOG_W as i32 / 2 - 90;
            if mx >= yes_x && mx < yes_x + 80 && my >= btn_y && my < btn_y + 30 {
                DIALOG_RESULT.store(RESULT_YES, Ordering::Relaxed);
                DIALOG_ACTIVE.store(false, Ordering::Relaxed);
                return true;
            }
            let no_x = x + DIALOG_W as i32 / 2 + 10;
            if mx >= no_x && mx < no_x + 80 && my >= btn_y && my < btn_y + 30 {
                DIALOG_RESULT.store(RESULT_NO, Ordering::Relaxed);
                DIALOG_ACTIVE.store(false, Ordering::Relaxed);
                return true;
            }
        }
        _ => {
            let ok_x = x + DIALOG_W as i32 / 2 - 40;
            if mx >= ok_x && mx < ok_x + 80 && my >= btn_y && my < btn_y + 30 {
                DIALOG_RESULT.store(RESULT_OK, Ordering::Relaxed);
                DIALOG_ACTIVE.store(false, Ordering::Relaxed);
                return true;
            }
        }
    }
    mx >= x && mx < x + DIALOG_W as i32 && my >= y && my < y + DIALOG_H as i32
}
