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

pub mod actions;
pub mod input;
pub mod menus;
pub mod render;
pub mod state;
pub mod types;

pub use input::{handle_click, update_hover};
pub(crate) use menus::get_items as get_menu_items;
pub use render::draw;
pub use state::{
    hide, is_visible, show, MENU_HEIGHT, MENU_HOVER_INDEX, MENU_ITEM_HEIGHT, MENU_PADDING,
    MENU_TYPE, MENU_WIDTH, MENU_X, MENU_Y,
};
pub use types::{ContextMenuType, MenuItemType};
