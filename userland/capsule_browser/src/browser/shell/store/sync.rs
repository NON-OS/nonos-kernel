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

use super::merge::Removed;
use crate::browser::shell::Shell;

/// Saves this window's state merged with whatever another window saved
/// since, then takes on the merged result so their additions show here too.
pub fn sync(shell: &mut Shell) {
    let removed = Removed { bookmarks: &shell.removed_bookmarks, groups: &shell.removed_groups };
    let merged = super::save::save(shell.persisted(), removed);
    shell.apply(merged);
}
