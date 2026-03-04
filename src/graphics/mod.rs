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

pub mod framebuffer;
pub mod font;
pub mod desktop;
pub mod cursor;
pub mod window;
pub mod backgrounds;
pub mod image;
pub mod themes;

pub use framebuffer::init as framebuffer_init;
pub use framebuffer::{
    get_pixel, put_pixel, fill_rect, clear, hline, vline, draw_rect, fill_rounded_rect,
    COLOR_BG, COLOR_FG, COLOR_ACCENT, COLOR_MENU_BG, COLOR_DOCK_BG, COLOR_WINDOW_BG,
    COLOR_TITLE_BG, COLOR_TITLE_FG, COLOR_WHITE, COLOR_BLACK, COLOR_RED, COLOR_GREEN,
    COLOR_BLUE, COLOR_GRAY, COLOR_DARK_GRAY, COLOR_LIGHT_GRAY,
};

pub use font::{CHAR_WIDTH, CHAR_HEIGHT, get_char_bitmap, draw_char, draw_text, draw_text_centered};

pub use desktop::{
    draw_all as desktop_draw_all, handle_menu_bar_click, handle_dock_click, handle_sidebar_click,
    update_clock, redraw_background,
};

pub use cursor::{draw as cursor_draw, erase as cursor_erase, hide as cursor_hide, show as cursor_show};

pub use window::{
    draw_window, draw_all as window_draw_all, redraw_focused, draw_string,
    handle_click, handle_drag, is_dragging, handle_key, is_editor_focused, is_terminal_focused,
    is_browser_focused, is_wallet_focused, is_text_input_focused, browser_special_key, wallet_special_key,
    update_notification_time, notify_info, notify_success, notify_warning, notify_error,
    has_notifications, show_info_dialog, show_warning_dialog, show_error_dialog, show_confirm_dialog,
    is_dialog_active, get_dialog_result, close_dialog, dialog_result, set_window_content_size,
    get_window_scroll, scroll_window_by, draw_window_scrollbar, editor_key,
    terminal_key, init as window_init,
    scroll, dialogs, notifications, text_editor, apps, terminal, browser,
};
