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

pub mod api;
pub mod input;
pub mod input_click;
pub mod input_focus;
pub mod input_keys;
pub mod input_resize;
pub mod input_snap;
pub mod manager;
pub mod manager_snap;
pub mod render;
pub mod state;

pub mod anim;
pub mod dialogs;
pub mod file_dialog;
pub mod notifications;
pub mod scroll;

pub mod vfs;

pub mod apps;
pub mod calculator;
pub mod calculator_input;
pub mod context_menu;
pub mod context_menu_input;
pub mod ecosystem;
pub mod file_manager;
pub mod settings;
pub mod shortcuts;
pub mod terminal;
pub mod text_editor;

pub use manager::{close, maximize, minimize, open};
pub use manager_snap::{snap_focused, snap_left, snap_right, snap_top, unsnap_focused};
pub use state::{window_type_from_u32, SnapZone, WindowType, FOCUSED_WINDOW, MAX_WINDOWS, WINDOWS};

pub use render::{draw_all, draw_string, draw_window, redraw_focused};

pub use input::{
    browser_special_key, ecosystem_special_key, file_manager_special_key, handle_click,
    handle_drag, handle_key, is_browser_focused, is_dragging, is_ecosystem_focused,
    is_editor_focused, is_file_manager_focused, is_terminal_focused, is_text_input_focused,
    is_wallet_focused, wallet_special_key,
};

pub use ecosystem::{get_active_tab as ecosystem_active_tab, EcosystemTab};

pub use api::{
    close_dialog, dialog_callback, dialog_result, draw_window_scrollbar, editor_key,
    get_dialog_input_callback, get_dialog_input_text, get_dialog_result, get_window_scroll,
    handle_dialog_key, has_notifications, is_dialog_active, is_input_dialog_active, notify_error,
    notify_info, notify_success, notify_warning, scroll_window_by, set_window_content_size,
    show_confirm_dialog, show_error_dialog, show_info_dialog, show_input_dialog,
    show_warning_dialog, update_notification_time,
};

pub use terminal::terminal_key;

pub use api::init;
pub use manager::{cycle_window, is_window_minimized, is_window_open, restore};
pub use settings::process_power_actions;
pub use shortcuts::handle_shortcut;

pub use file_manager::{
    copy_selected as fm_copy_selected, create_folder as fm_create_folder,
    cut_selected as fm_cut_selected, delete_selected as fm_delete_selected,
    navigate_to as fm_navigate_to, open_selected as fm_open_selected, paste as fm_paste,
    rename_selected as fm_rename_selected,
};

pub use text_editor::editor_open as text_editor_open_file;
