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

use crate::browser::net::mixnet;
use crate::browser::paint::tokens::mode;
use crate::browser::settings::NETWORKS;
use crate::browser::shell::kept::MAX_SIZE;
use crate::browser::shell::types::DlState;
use crate::browser::shell::Shell;
use crate::browser::state::State;
use crate::browser::ui::settings_geom::Control;

/* How a button is drawn: the choice in force, another choice, a plain
 * button, one that removes, that one waiting for its second click, or one
 * with nothing to act on. */
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Look {
    On,
    Off,
    Plain,
    Danger,
    Armed,
    Dim,
}

/// How the button for `c` is drawn now.
pub fn look(state: &State, shell: &Shell, c: Control) -> Look {
    let pick = |on: bool| if on { Look::On } else { Look::Off };
    let can = |on: bool| if on { Look::Plain } else { Look::Dim };
    let r = &shell.reader;
    match c {
        Control::Appearance(i) => pick(i == mode() as u8),
        Control::Network(i) => pick(NETWORKS.get(i as usize) == Some(&mixnet::chosen())),
        Control::Search(i) => pick((i == 1) == shell.search.is_some()),
        Control::ReaderTheme(i) => pick(i == r.theme),
        Control::ReaderWidth(i) => pick(i == r.width),
        Control::Smaller => can(r.size > 0),
        Control::Larger => can(r.size < MAX_SIZE),
        Control::ProxyOff => can(state.proxy.is_some()),
        Control::ClearHistory => can(!shell.visits.is_empty()),
        Control::ClearDownloads => can(shell.downloads.iter().any(|d| d.state != DlState::Saving)),
        Control::RemoveBookmarks if shell.bookmarks.is_empty() => Look::Dim,
        Control::RemoveBookmarks if shell.settings.armed => Look::Armed,
        Control::RemoveBookmarks => Look::Danger,
        Control::ProxySet | Control::SearchUse | Control::Field(_) => Look::Plain,
    }
}
