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
use crate::graphics::framebuffer::dimensions;
use core::sync::atomic::Ordering;

const NOTIF_W: u32 = 320;
const NOTIF_H: u32 = 60;
const PADDING: u32 = 12;

pub(crate) fn handle_click(mx: i32, my: i32) -> bool {
    let (sw, _) = dimensions();
    let start_x = (sw - NOTIF_W - PADDING) as i32;
    let start_y = 48i32;
    let mut drawn = 0i32;

    unsafe {
        for i in 0..MAX_NOTIFICATIONS {
            if NOTIFICATIONS[i].active {
                let y = start_y + drawn * (NOTIF_H as i32 + PADDING as i32);
                let close_x = start_x + NOTIF_W as i32 - 20;
                if mx >= close_x && mx < close_x + 14 && my >= y + 5 && my < y + 19 {
                    NOTIFICATIONS[i].active = false;
                    NOTIFICATION_COUNT.fetch_sub(1, Ordering::Relaxed);
                    return true;
                }
                if mx >= start_x
                    && mx < start_x + NOTIF_W as i32
                    && my >= y
                    && my < y + NOTIF_H as i32
                {
                    return true;
                }
                drawn += 1;
            }
        }
    }
    false
}
