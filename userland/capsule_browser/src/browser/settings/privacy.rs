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

use crate::browser::shell::settings_ui::{press, Press};
use crate::browser::shell::store;
use crate::browser::shell::types::DlState;
use crate::browser::shell::Shell;
use crate::browser::ui::settings_geom::Control;

/// Clear history now, Clear download list and Remove all bookmarks. The
/// download list keeps a save still being written, which updates its own
/// record when it lands; the files on disk stay. Removing the bookmarks
/// takes a second click, and is saved so another window's merge does not
/// bring them back.
pub(super) fn clear(shell: &mut Shell, ctl: Control) {
    match ctl {
        Control::ClearHistory => shell.visits.clear(),
        Control::ClearDownloads => shell.downloads.retain(|d| d.state == DlState::Saving),
        _ => match press(shell.settings.armed, shell.bookmarks.len()) {
            Press::Arm => shell.settings.armed = true,
            Press::Clear => {
                shell.settings.armed = false;
                shell.remove_all_bookmarks();
                store::sync(shell);
            }
            Press::Nothing => {}
        },
    }
}
