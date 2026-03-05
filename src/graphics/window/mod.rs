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

pub mod state;
pub mod manager;
pub mod manager_snap;
pub mod render;
pub mod input;
pub mod input_click;
pub mod input_keys;
pub mod input_snap;
pub mod input_resize;
pub mod input_focus;
pub mod api;

pub mod scroll;
pub mod dialogs;
pub mod notifications;

pub mod vfs;

pub mod calculator;
pub mod calculator_input;
pub mod file_manager;
pub mod text_editor;
pub mod settings;
pub mod apps;
pub mod terminal;
pub mod browser;
pub mod ecosystem;
pub mod shortcuts;
pub mod context_menu;
pub mod context_menu_input;

pub use state::{WindowType, WINDOWS, FOCUSED_WINDOW, MAX_WINDOWS, window_type_from_u32, SnapZone};
pub use manager::{open, close, minimize, maximize};
pub use manager_snap::{snap_focused, snap_left, snap_right, snap_top, unsnap_focused};

pub use render::{
    draw_window,
    draw_all,
    redraw_focused,
    draw_string,
};

pub use input::{
    handle_click,
    handle_drag,
    is_dragging,
    handle_key,
    is_editor_focused,
    is_terminal_focused,
    is_browser_focused,
    is_wallet_focused,
    is_ecosystem_focused,
    is_file_manager_focused,
    is_text_input_focused,
    browser_special_key,
    wallet_special_key,
    ecosystem_special_key,
    file_manager_special_key,
};

pub use ecosystem::{EcosystemTab, get_active_tab as ecosystem_active_tab};

pub use api::{
    update_notification_time,
    notify_info,
    notify_success,
    notify_warning,
    notify_error,
    has_notifications,
    show_info_dialog,
    show_warning_dialog,
    show_error_dialog,
    show_confirm_dialog,
    is_dialog_active,
    get_dialog_result,
    close_dialog,
    dialog_result,
    set_window_content_size,
    get_window_scroll,
    scroll_window_by,
    draw_window_scrollbar,
    editor_key,
};

pub use terminal::terminal_key;

pub use shortcuts::handle_shortcut;
pub use manager::is_window_open;
pub use settings::process_power_actions;
pub use api::init;

pub use file_manager::{
    open_selected as fm_open_selected,
    copy_selected as fm_copy_selected,
    cut_selected as fm_cut_selected,
    paste as fm_paste,
    delete_selected as fm_delete_selected,
    create_folder as fm_create_folder,
};
