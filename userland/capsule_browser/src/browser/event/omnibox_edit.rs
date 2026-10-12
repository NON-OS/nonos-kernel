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

use alloc::string::String;

use crate::browser::omnibox::EditKey;
use crate::browser::state::State;

/* Apply an editing key to the address bar. Returns whether the text, caret
 * or selection changed. A clipboard that is not there says so in the
 * status line instead of failing quietly. */
pub(super) fn apply(state: &mut State, k: EditKey) -> bool {
    match super::line_keys::edit(&mut state.ui.omnibox, k) {
        Ok(changed) => changed,
        Err(e) => {
            state.tell(String::from(e));
            false
        }
    }
}
