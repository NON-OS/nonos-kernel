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

use core::ptr::addr_of_mut;
use core::sync::atomic::Ordering;
use crate::graphics::framebuffer::dimensions;
use super::state::{WindowType, WINDOWS, FOCUSED_WINDOW, MAX_WINDOWS, NEXT_WINDOW_OFFSET};
use super::scroll;
use super::vfs::{self, init_vfs};
use super::file_manager::{FM_CURRENT_DIR, FM_SELECTED_ITEM};
use super::text_editor::{EDITOR_LEN, EDITOR_CURSOR, EDITOR_MODIFIED, EDITOR_BUFFER, BUFFER_SIZE};


fn get_window_dimensions(wtype: WindowType) -> (u32, u32) {
    match wtype {
        WindowType::Calculator => (280, 380),
        WindowType::FileManager => (550, 420),
        WindowType::TextEditor => (600, 450),
        WindowType::Settings => (550, 450),
        WindowType::About => (420, 400),
        WindowType::ProcessManager => (520, 420),
        WindowType::Browser => (700, 500),
        WindowType::Terminal => (650, 450),
        WindowType::Wallet => (650, 500),
        WindowType::Ecosystem => (850, 600),
        WindowType::None => (0, 0),
    }
}

fn init_window_state(wtype: WindowType) {
    match wtype {
        WindowType::FileManager => {
            FM_CURRENT_DIR.store(0, Ordering::Relaxed);
            FM_SELECTED_ITEM.store(255, Ordering::Relaxed);
            if vfs::VFS_COUNT.load(Ordering::Relaxed) == 0 {
                init_vfs();
            }
        }
        WindowType::TextEditor => {
            EDITOR_LEN.store(0, Ordering::Relaxed);
            EDITOR_CURSOR.store(0, Ordering::Relaxed);
            EDITOR_MODIFIED.store(false, Ordering::Relaxed);
            let default_text = b"// Welcome to N\xd8NOS Editor\n// Type here to edit\n\nfn main() {\n    println!(\"Hello, N\xd8NOS!\");\n}\n";
            // SAFETY: Single-threaded window initialization
            unsafe {
                let ptr = addr_of_mut!(EDITOR_BUFFER) as *mut u8;
                let len = default_text.len().min(BUFFER_SIZE);
                core::ptr::copy_nonoverlapping(default_text.as_ptr(), ptr, len);
            }
            EDITOR_LEN.store(default_text.len(), Ordering::Relaxed);
        }
        WindowType::Terminal => {
            super::terminal::init();
        }
        WindowType::Settings => {
            super::settings::reset_render_state();
        }
        _ => {}
    }
}

pub fn open(wtype: WindowType) -> Option<usize> {
    if matches!(wtype, WindowType::None) {
        return None;
    }

    for i in 0..MAX_WINDOWS {
        if WINDOWS[i].active.load(Ordering::Relaxed) {
            if WINDOWS[i].window_type.load(Ordering::Relaxed) == wtype as u32 {
                FOCUSED_WINDOW.store(i, Ordering::Relaxed);
                return Some(i);
            }
        }
    }

    for i in 0..MAX_WINDOWS {
        if !WINDOWS[i].active.load(Ordering::Relaxed) {
            let (screen_w, screen_h) = dimensions();
            let offset = NEXT_WINDOW_OFFSET.fetch_add(30, Ordering::Relaxed) % 150;
            let (win_w, win_h) = get_window_dimensions(wtype);

            if win_w == 0 || win_h == 0 {
                return None;
            }

            let x = ((screen_w as i32 - win_w as i32) / 2 + offset).max(60);
            let y = ((screen_h as i32 - win_h as i32) / 2 + offset).max(40);

            WINDOWS[i].active.store(true, Ordering::Relaxed);
            WINDOWS[i].window_type.store(wtype as u32, Ordering::Relaxed);
            WINDOWS[i].x.store(x, Ordering::Relaxed);
            WINDOWS[i].y.store(y, Ordering::Relaxed);
            WINDOWS[i].width.store(win_w, Ordering::Relaxed);
            WINDOWS[i].height.store(win_h, Ordering::Relaxed);
            WINDOWS[i].dragging.store(false, Ordering::Relaxed);
            WINDOWS[i].minimized.store(false, Ordering::Relaxed);
            WINDOWS[i].maximized.store(false, Ordering::Relaxed);

            scroll::reset(i);
            FOCUSED_WINDOW.store(i, Ordering::Relaxed);

            init_window_state(wtype);

            return Some(i);
        }
    }
    None
}

pub fn close(idx: usize) {
    if idx < MAX_WINDOWS {
        WINDOWS[idx].active.store(false, Ordering::Relaxed);
        scroll::reset(idx);
        if FOCUSED_WINDOW.load(Ordering::Relaxed) == idx {
            let mut next_focus = MAX_WINDOWS;
            for i in 0..MAX_WINDOWS {
                if i != idx && WINDOWS[i].active.load(Ordering::Relaxed) {
                    next_focus = i;
                    break;
                }
            }
            FOCUSED_WINDOW.store(next_focus, Ordering::Relaxed);
        }
    }
}

pub fn focus(idx: usize) {
    if idx < MAX_WINDOWS && WINDOWS[idx].active.load(Ordering::Relaxed) {
        FOCUSED_WINDOW.store(idx, Ordering::Relaxed);
    }
}

pub fn minimize(idx: usize) {
    if idx < MAX_WINDOWS && WINDOWS[idx].active.load(Ordering::Relaxed) {
        WINDOWS[idx].minimized.store(true, Ordering::Relaxed);
        if FOCUSED_WINDOW.load(Ordering::Relaxed) == idx {
            for i in 0..MAX_WINDOWS {
                if i != idx && WINDOWS[i].active.load(Ordering::Relaxed)
                    && !WINDOWS[i].minimized.load(Ordering::Relaxed) {
                    FOCUSED_WINDOW.store(i, Ordering::Relaxed);
                    return;
                }
            }
            FOCUSED_WINDOW.store(MAX_WINDOWS, Ordering::Relaxed);
        }
    }
}

pub fn maximize(idx: usize) {
    if idx >= MAX_WINDOWS || !WINDOWS[idx].active.load(Ordering::Relaxed) {
        return;
    }

    let (screen_w, screen_h) = dimensions();
    let is_maximized = WINDOWS[idx].maximized.load(Ordering::Relaxed);

    if is_maximized {
        let x = WINDOWS[idx].pre_max_x.load(Ordering::Relaxed);
        let y = WINDOWS[idx].pre_max_y.load(Ordering::Relaxed);
        let w = WINDOWS[idx].pre_max_w.load(Ordering::Relaxed);
        let h = WINDOWS[idx].pre_max_h.load(Ordering::Relaxed);

        WINDOWS[idx].x.store(x, Ordering::Relaxed);
        WINDOWS[idx].y.store(y, Ordering::Relaxed);
        WINDOWS[idx].width.store(w, Ordering::Relaxed);
        WINDOWS[idx].height.store(h, Ordering::Relaxed);
        WINDOWS[idx].maximized.store(false, Ordering::Relaxed);
    } else {
        let x = WINDOWS[idx].x.load(Ordering::Relaxed);
        let y = WINDOWS[idx].y.load(Ordering::Relaxed);
        let w = WINDOWS[idx].width.load(Ordering::Relaxed);
        let h = WINDOWS[idx].height.load(Ordering::Relaxed);

        WINDOWS[idx].pre_max_x.store(x, Ordering::Relaxed);
        WINDOWS[idx].pre_max_y.store(y, Ordering::Relaxed);
        WINDOWS[idx].pre_max_w.store(w, Ordering::Relaxed);
        WINDOWS[idx].pre_max_h.store(h, Ordering::Relaxed);

        const DOCK_WIDTH: i32 = 60;
        const MENUBAR_HEIGHT: i32 = 32;
        const PADDING: i32 = 8;

        let max_x = DOCK_WIDTH + PADDING;
        let max_y = MENUBAR_HEIGHT + PADDING;
        let max_w = (screen_w as i32 - DOCK_WIDTH - PADDING * 2) as u32;
        let max_h = (screen_h as i32 - MENUBAR_HEIGHT - PADDING * 2) as u32;

        WINDOWS[idx].x.store(max_x, Ordering::Relaxed);
        WINDOWS[idx].y.store(max_y, Ordering::Relaxed);
        WINDOWS[idx].width.store(max_w, Ordering::Relaxed);
        WINDOWS[idx].height.store(max_h, Ordering::Relaxed);
        WINDOWS[idx].maximized.store(true, Ordering::Relaxed);
    }

    scroll::reset(idx);
}

pub fn is_window_open(wtype: WindowType) -> bool {
    if matches!(wtype, WindowType::None) {
        return false;
    }

    for i in 0..MAX_WINDOWS {
        if WINDOWS[i].active.load(Ordering::Relaxed) {
            if WINDOWS[i].window_type.load(Ordering::Relaxed) == wtype as u32 {
                return true;
            }
        }
    }
    false
}
