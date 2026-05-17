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

use crate::window::{Visibility, Window, WindowTable};

// Returns the (owner_pid, window_id) of the topmost visible window
// whose rect contains (px, py). Used by the input_router via a
// FOCUS_QUERY call to resolve pointer routing on each event.
pub fn topmost_at(table: &WindowTable, px: u32, py: u32) -> Option<(u32, u32)> {
    let mut best: Option<&Window> = None;
    for w in table.windows() {
        if w.visibility != Visibility::Visible {
            continue;
        }
        if !w.rect.contains(px, py) {
            continue;
        }
        if !w.kind.focusable() {
            continue;
        }
        best = Some(match best {
            None => w,
            Some(cur) if w.z > cur.z => w,
            Some(cur) => cur,
        });
    }
    best.map(|w| (w.owner_pid, w.window_id))
}
