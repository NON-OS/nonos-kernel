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

pub mod types;
pub mod actions;
pub mod menus;
pub mod state;
pub mod render;
pub mod input;

pub use types::{MenuItemType, ContextMenuType};
pub use state::{show, hide, is_visible, MENU_ITEM_HEIGHT, MENU_PADDING,
    MENU_X, MENU_Y, MENU_WIDTH, MENU_HEIGHT, MENU_TYPE, MENU_HOVER_INDEX};
pub use render::draw;
pub use input::{update_hover, handle_click};
pub(crate) use menus::get_items as get_menu_items;
