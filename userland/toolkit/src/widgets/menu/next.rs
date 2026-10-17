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

//! Moving a menu's highlighted row with the arrow keys.

use super::{Item, Menu};

impl Menu<'_> {
    /// The live item `step` live items on from `from`: down the list for a
    /// positive step, up it for a negative one, wrapping round the ends and
    /// stepping over separators and disabled items. From `None`, or an index
    /// past the end, one step down lands on the first live item and one step
    /// up on the last. A step of 0 gives `from` back when it is live. `None`
    /// when no item is live. The app keeps the result as its highlighted row
    /// and passes it to `hovered`.
    pub fn next(items: &[Item], from: Option<usize>, step: i32) -> Option<usize> {
        let n = items.len();
        let live = items.iter().filter(|it| it.live()).count();
        let mut at = from.filter(|&i| i < n);
        if live == 0 || step == 0 {
            return at.filter(|&i| items[i].live());
        }
        let down = step > 0;
        let steps = (step.unsigned_abs() as usize - 1) % live + 1;
        for _ in 0..steps {
            let start = at.unwrap_or(if down { n - 1 } else { 0 });
            let to = |k: usize| if down { (start + k) % n } else { (start + n - k) % n };
            at = (1..=n).map(to).find(|&i| items[i].live());
        }
        at
    }
}
