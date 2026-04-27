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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuItemType {
    Action,
    Separator,
    Disabled,
}

#[derive(Clone, Copy)]
pub struct MenuItem {
    pub label: &'static [u8],
    pub item_type: MenuItemType,
    pub action_id: u8,
}

impl MenuItem {
    pub const fn action(label: &'static [u8], action_id: u8) -> Self {
        Self { label, item_type: MenuItemType::Action, action_id }
    }
    pub const fn separator() -> Self {
        Self { label: b"", item_type: MenuItemType::Separator, action_id: 0 }
    }
    pub const fn disabled(label: &'static [u8]) -> Self {
        Self { label, item_type: MenuItemType::Disabled, action_id: 0 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContextMenuType {
    None = 0,
    Desktop = 1,
    FileManager = 2,
    TextEditor = 3,
    Window = 4,
}
