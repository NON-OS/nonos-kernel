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

// Frontend stack — framebuffer, fonts, cursor, desktop, window system,
// drm, clipboard. This is where new graphics work lands.

pub mod animation;
pub mod backgrounds;
pub mod clipboard;
pub mod components;
pub mod cursor;
pub mod design_system;
pub mod desktop;
pub mod font;
pub mod framebuffer;
pub mod image;
pub mod login;
pub mod qrcode;
pub mod spotlight;
pub mod themes;
pub mod window;

#[cfg(test)]
pub mod tests;

pub use framebuffer::dimensions as framebuffer_dimensions;
pub use framebuffer::init as framebuffer_init;
pub use framebuffer::{
    clear, draw_rect, fill_rect, fill_rounded_rect, get_pixel, hline, put_pixel, vline,
    COLOR_ACCENT, COLOR_BG, COLOR_BLACK, COLOR_BLUE, COLOR_DARK_GRAY, COLOR_DOCK_BG, COLOR_FG,
    COLOR_GRAY, COLOR_GREEN, COLOR_LIGHT_GRAY, COLOR_MENU_BG, COLOR_RED, COLOR_TITLE_BG,
    COLOR_TITLE_FG, COLOR_WHITE, COLOR_WINDOW_BG,
};

pub use font::{
    draw_char, draw_text, draw_text_centered, get_char_bitmap, CHAR_HEIGHT, CHAR_WIDTH,
};

pub use desktop::{
    draw_all as desktop_draw_all, handle_dock_click, handle_menu_bar_click, handle_sidebar_click,
    redraw_background, update_clock,
};

pub use cursor::{
    draw as cursor_draw, erase as cursor_erase, hide as cursor_hide, show as cursor_show,
};

pub use window::{
    apps, browser_special_key, close_dialog, dialog_result, dialogs, draw_all as window_draw_all,
    draw_string, draw_window, draw_window_scrollbar, editor_key, get_dialog_result,
    get_window_scroll, handle_click, handle_drag, handle_key, has_notifications,
    init as window_init, is_browser_focused, is_dialog_active, is_dragging, is_editor_focused,
    is_terminal_focused, is_text_input_focused, is_wallet_focused, notifications, notify_error,
    notify_info, notify_success, notify_warning, redraw_focused, scroll, scroll_window_by,
    set_window_content_size, show_confirm_dialog, show_error_dialog, show_info_dialog,
    show_warning_dialog, terminal, terminal_key, text_editor, update_notification_time,
    wallet_special_key,
};

use core::sync::atomic::{AtomicBool, Ordering};

static GRAPHICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_graphics_subsystem() -> Result<(), &'static str> {
    if GRAPHICS_INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    framebuffer::init();

    if let Err(e) = drm::init_drm_subsystem() {
        crate::log_info!("DRM: {}", e);
    }

    window_init();
    cursor::init();

    Ok(())
}
