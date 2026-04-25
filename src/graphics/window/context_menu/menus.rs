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

use super::actions;
use super::types::{ContextMenuType, MenuItem};

static MENU_DESKTOP: [MenuItem; 9] = [
    MenuItem::action(b"Go Back", actions::DESKTOP_GO_BACK),
    MenuItem::action(b"New Folder", actions::DESKTOP_NEW_FOLDER),
    MenuItem::action(b"New File", actions::DESKTOP_NEW_FILE),
    MenuItem::separator(),
    MenuItem::action(b"Delete", actions::DESKTOP_DELETE),
    MenuItem::separator(),
    MenuItem::action(b"Refresh", actions::DESKTOP_REFRESH),
    MenuItem::action(b"Settings", actions::DESKTOP_SETTINGS),
    MenuItem::action(b"About N\xd8NOS", actions::DESKTOP_ABOUT),
];

static MENU_FILE_MANAGER: [MenuItem; 10] = [
    MenuItem::action(b"Open", actions::FM_OPEN),
    MenuItem::separator(),
    MenuItem::action(b"Cut", actions::FM_CUT),
    MenuItem::action(b"Copy", actions::FM_COPY),
    MenuItem::action(b"Paste", actions::FM_PASTE),
    MenuItem::separator(),
    MenuItem::action(b"Delete", actions::FM_DELETE),
    MenuItem::action(b"Rename", actions::FM_RENAME),
    MenuItem::separator(),
    MenuItem::action(b"New Folder", actions::FM_NEW_FOLDER),
];

static MENU_TEXT_EDITOR: [MenuItem; 5] = [
    MenuItem::action(b"Cut", actions::EDIT_CUT),
    MenuItem::action(b"Copy", actions::EDIT_COPY),
    MenuItem::action(b"Paste", actions::EDIT_PASTE),
    MenuItem::separator(),
    MenuItem::action(b"Select All", actions::EDIT_SELECT_ALL),
];

static MENU_WINDOW: [MenuItem; 4] = [
    MenuItem::action(b"Minimize", actions::WIN_MINIMIZE),
    MenuItem::action(b"Maximize", actions::WIN_MAXIMIZE),
    MenuItem::separator(),
    MenuItem::action(b"Close", actions::WIN_CLOSE),
];

static MENU_EMPTY: [MenuItem; 0] = [];

pub fn get_items(menu_type: ContextMenuType) -> &'static [MenuItem] {
    match menu_type {
        ContextMenuType::Desktop => &MENU_DESKTOP,
        ContextMenuType::FileManager => &MENU_FILE_MANAGER,
        ContextMenuType::TextEditor => &MENU_TEXT_EDITOR,
        ContextMenuType::Window => &MENU_WINDOW,
        ContextMenuType::None => &MENU_EMPTY,
    }
}
