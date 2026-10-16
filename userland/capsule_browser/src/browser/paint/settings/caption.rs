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

use alloc::format;
use alloc::string::String;

use crate::browser::shell::Shell;
use crate::browser::ui::settings_geom::Control;

const APPEARANCE: [&str; 3] = ["Light", "Dark", "System"];
const NETWORKS: [&str; 3] = ["Mixnet (Nym)", "Anyone", "Direct"];
const ENGINES: [&str; 2] = ["DuckDuckGo", "Custom"];
const THEMES: [&str; 3] = ["Light", "Sepia", "Dark"];
const WIDTHS: [&str; 3] = ["Narrow", "Standard", "Wide"];

/// What the button for `c` says. Remove all bookmarks, once armed, asks
/// for the second click and names how many go.
pub fn caption(shell: &Shell, c: Control) -> String {
    let pick = |names: &[&str], i: u8| String::from(names.get(i as usize).copied().unwrap_or(""));
    match c {
        Control::Appearance(i) => pick(&APPEARANCE, i),
        Control::Network(i) => pick(&NETWORKS, i),
        Control::Search(i) => pick(&ENGINES, i),
        Control::ReaderTheme(i) => pick(&THEMES, i),
        Control::ReaderWidth(i) => pick(&WIDTHS, i),
        Control::ProxySet => String::from("Set"),
        Control::ProxyOff => String::from("Off"),
        Control::SearchUse => String::from("Use"),
        Control::ClearHistory => String::from("Clear history now"),
        Control::ClearDownloads => String::from("Clear download list"),
        Control::RemoveBookmarks if shell.settings.armed => match shell.bookmarks.len() {
            1 => String::from("Click again to remove 1 bookmark"),
            n => format!("Click again to remove {} bookmarks", n),
        },
        Control::RemoveBookmarks => String::from("Remove all bookmarks"),
        Control::Field(_) | Control::Smaller | Control::Larger => String::new(),
    }
}
