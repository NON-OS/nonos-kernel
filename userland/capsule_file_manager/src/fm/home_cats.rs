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

use nonos_toolkit::widgets::Ink;

use super::icon_path::Icon;
use super::screen::Screen;

/// One Home category. `path` is both the store prefix its figure is counted
/// from and the place a click browses to; `screen` is a surface a click switches
/// to instead. `counted` says whether anything behind the card can produce a
/// figure at all -- a card with no backend draws dimmed and states that, rather
/// than showing a number nothing measured.
pub struct Cat {
    pub title: &'static str,
    pub icon: Icon,
    pub tint: Ink,
    pub path: Option<&'static str>,
    pub screen: Option<Screen>,
    pub counted: bool,
}

const fn cat(
    title: &'static str,
    icon: Icon,
    tint: Ink,
    path: Option<&'static str>,
    screen: Option<Screen>,
    counted: bool,
) -> Cat {
    Cat { title, icon, tint, path, screen, counted }
}

/// The category row, in drawn order. Recents counts the access journal and the
/// three prefix cards count their own subtree. There is no Shared card: the
/// capsule holds no identity or sharing backend, so it would have no files.
pub const CATS: [Cat; 4] = [
    cat("Recents", Icon::Clock, Ink::Text2, None, Some(Screen::Recents), true),
    cat("Projects", Icon::Folder, Ink::Warn, Some("/projects/"), None, true),
    cat("Downloads", Icon::Download, Ink::Ok, Some("/downloads/"), None, true),
    cat("Capsules", Icon::Cube, Ink::Accent, Some("/capsules/"), None, true),
];
