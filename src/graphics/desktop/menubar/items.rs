// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

#[derive(Clone, Copy)]
pub(super) struct MenuItem {
    pub label: &'static [u8],
    pub shortcut: Option<&'static [u8]>,
    pub separator_after: bool,
    pub enabled: bool,
}

impl MenuItem {
    pub(super) const fn new(label: &'static [u8]) -> Self {
        Self { label, shortcut: None, separator_after: false, enabled: true }
    }
    pub(super) const fn with_shortcut(mut self, s: &'static [u8]) -> Self {
        self.shortcut = Some(s);
        self
    }
    pub(super) const fn separator(mut self) -> Self {
        self.separator_after = true;
        self
    }
}

pub(super) static FILE_MENU: &[MenuItem] = &[
    MenuItem::new(b"New Window").with_shortcut(b"Ctrl+N"),
    MenuItem::new(b"New Tab").with_shortcut(b"Ctrl+T").separator(),
    MenuItem::new(b"Open...").with_shortcut(b"Ctrl+O"),
    MenuItem::new(b"Save").with_shortcut(b"Ctrl+S"),
    MenuItem::new(b"Save As...").with_shortcut(b"Ctrl+Shift+S").separator(),
    MenuItem::new(b"Close Window").with_shortcut(b"Ctrl+W"),
];

pub(super) static EDIT_MENU: &[MenuItem] = &[
    MenuItem::new(b"Undo").with_shortcut(b"Ctrl+Z"),
    MenuItem::new(b"Redo").with_shortcut(b"Ctrl+Y").separator(),
    MenuItem::new(b"Cut").with_shortcut(b"Ctrl+X"),
    MenuItem::new(b"Copy").with_shortcut(b"Ctrl+C"),
    MenuItem::new(b"Paste").with_shortcut(b"Ctrl+V").separator(),
    MenuItem::new(b"Select All").with_shortcut(b"Ctrl+A"),
    MenuItem::new(b"Find...").with_shortcut(b"Ctrl+F"),
];

pub(super) static VIEW_MENU: &[MenuItem] = &[
    MenuItem::new(b"Zoom In").with_shortcut(b"Ctrl++"),
    MenuItem::new(b"Zoom Out").with_shortcut(b"Ctrl+-"),
    MenuItem::new(b"Reset Zoom").with_shortcut(b"Ctrl+0").separator(),
    MenuItem::new(b"Full Screen").with_shortcut(b"F11"),
    MenuItem::new(b"Toggle Sidebar").with_shortcut(b"Ctrl+B"),
];

pub(super) static WINDOW_MENU: &[MenuItem] = &[
    MenuItem::new(b"Minimize").with_shortcut(b"Ctrl+M"),
    MenuItem::new(b"Maximize"),
    MenuItem::new(b"Close").with_shortcut(b"Ctrl+W").separator(),
    MenuItem::new(b"Tile Left").with_shortcut(b"Super+Left"),
    MenuItem::new(b"Tile Right").with_shortcut(b"Super+Right"),
];

pub(super) static HELP_MENU: &[MenuItem] = &[
    MenuItem::new(b"Documentation"),
    MenuItem::new(b"Keyboard Shortcuts").separator(),
    MenuItem::new(b"Report Issue"),
    MenuItem::new(b"About NONOS"),
];
