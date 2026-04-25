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

use crate::graphics::window::context_menu::ContextMenuType;
use crate::graphics::window::{
    window_type_from_u32, WindowType, FOCUSED_WINDOW, MAX_WINDOWS, WINDOWS,
};
use core::sync::atomic::Ordering;

pub fn get_context_menu_type(mx: i32, my: i32) -> ContextMenuType {
    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);
    if focused < MAX_WINDOWS && WINDOWS[focused].active.load(Ordering::Relaxed) {
        let wx = WINDOWS[focused].x.load(Ordering::Relaxed);
        let wy = WINDOWS[focused].y.load(Ordering::Relaxed);
        let ww = WINDOWS[focused].width.load(Ordering::Relaxed) as i32;
        let wh = WINDOWS[focused].height.load(Ordering::Relaxed) as i32;
        if mx >= wx && mx < wx + ww && my >= wy && my < wy + wh {
            let wtype = window_type_from_u32(WINDOWS[focused].window_type.load(Ordering::Relaxed));
            return match wtype {
                WindowType::FileManager => ContextMenuType::FileManager,
                WindowType::TextEditor => ContextMenuType::TextEditor,
                _ => ContextMenuType::Window,
            };
        }
    }
    for i in (0..MAX_WINDOWS).rev() {
        if WINDOWS[i].active.load(Ordering::Relaxed)
            && !WINDOWS[i].minimized.load(Ordering::Relaxed)
        {
            let wx = WINDOWS[i].x.load(Ordering::Relaxed);
            let wy = WINDOWS[i].y.load(Ordering::Relaxed);
            let ww = WINDOWS[i].width.load(Ordering::Relaxed) as i32;
            let wh = WINDOWS[i].height.load(Ordering::Relaxed) as i32;
            if mx >= wx && mx < wx + ww && my >= wy && my < wy + wh {
                return ContextMenuType::Window;
            }
        }
    }
    ContextMenuType::Desktop
}
