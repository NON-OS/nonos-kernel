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

//! Moving a dialog's focus between its buttons with Tab and Shift-Tab.

use super::Dialog;

impl Dialog<'_> {
    /// The button `step` buttons on from `from` among `count`: right for a
    /// positive step, as Tab moves, and left for a negative one, as
    /// Shift-Tab moves, wrapping round the ends. From an index past the
    /// last, one step right lands on the first button and one step left on
    /// the last, and a step of 0 gives `from` or, past the last, the last.
    /// `None` when there is no button. The app keeps the result
    /// and passes it to `focus`.
    pub fn next_focus(count: usize, from: usize, step: i32) -> Option<usize> {
        if count == 0 {
            return None;
        }
        let n = count as i64;
        let past = if step < 0 { n } else { -1 };
        let start = if from < count { from as i64 } else { past };
        Some((start + i64::from(step)).rem_euclid(n) as usize)
    }
}
