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

use crate::process::{current_uid, get_uid};

/// POSIX permission for one process to signal another. Root may signal
/// any target; a non-root caller may signal a target whose uid matches.
pub(super) fn may_signal(target: u32) -> bool {
    let sender_uid = current_uid();
    if sender_uid == 0 {
        return true;
    }
    match get_uid(target) {
        Some(t) => t == sender_uid,
        None => false,
    }
}
