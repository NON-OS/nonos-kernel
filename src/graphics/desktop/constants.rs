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

use crate::graphics::window::WindowType;

pub(crate) const MENU_BAR_HEIGHT: u32 = 34;
pub(crate) const DOCK_HEIGHT: u32 = 64;
pub(crate) const SIDEBAR_WIDTH: u32 = 60;
pub(super) const DOCK_WIDTH: u32 = 520;
pub(super) const DOCK_INNER_HEIGHT: u32 = 52;
pub(super) const DOCK_ICON_COUNT: usize = 9;

pub(super) const DOCK_ICONS: [WindowType; DOCK_ICON_COUNT] = [
    WindowType::Terminal,
    WindowType::FileManager,
    WindowType::TextEditor,
    WindowType::Calculator,
    WindowType::Wallet,
    WindowType::ProcessManager,
    WindowType::Settings,
    WindowType::Browser,
    WindowType::About,
];
