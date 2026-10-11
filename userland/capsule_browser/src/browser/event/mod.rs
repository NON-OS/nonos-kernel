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

mod anchor;
mod dialog_line;
mod dom_print;
mod enclosing_form;
mod field_at;
mod field_key;
mod field_room;
mod field_toggle;
mod field_value;
mod follow_link;
mod form_fields;
mod form_send;
mod js_click;
mod js_tick;
mod key_names;
mod label_for;
mod link_under;
mod local;
mod nav_history;
mod navigate;
mod omnibox_commit;
mod omnibox_edit;
mod on_button;
mod on_event;
mod on_home_click;
mod on_key;
mod on_keydown;
mod on_page_click;
mod on_page_key;
mod on_pointer;
mod on_toolbar;
mod page_input;
mod pill_caret;
mod relayout;
mod script_dialog;
mod script_nav;
mod script_stop;
mod scroll_by;
pub(crate) mod select_list;
mod select_open;
mod stop;
mod submit_form;
mod tab_focus;
mod timer_gate;
mod toggle_field;

pub(crate) use field_value::{control_value, set_control_value};
pub use js_tick::js_tick;
pub use on_event::on_event;
pub use relayout::relayout;
pub use script_nav::take_script_nav;
pub use script_stop::script_stop;
pub use select_open::{placed as select_placed, PX as SELECT_PX};
