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

//! Table: the pixels one change to a table paints, and what `hit` names
//! on them, for the hit and cell proofs.

use nonos_toolkit::widgets::{Cell, Rect, Table};

use super::canvas::Canvas;

/// About 128 of the pixels `lit` changes from `t`, spread evenly through
/// them, the last among them, or a line when it changes none and `need`.
pub(crate) fn probes(
    t: Table,
    lit: Table,
    at: Rect,
    need: bool,
) -> Result<Vec<(i32, i32)>, String> {
    let draw = |t: Table| Canvas::new(at, 0).painted(|fb| t.draw(fb, at));
    let changed = draw(lit).diff(&draw(t));
    let step = changed.len().div_ceil(128).max(1);
    let each = changed.iter().step_by(step).chain(changed.last());
    let probes: Vec<_> = each.map(|&(x, y)| (x as i32, y as i32)).collect();
    if probes.is_empty() && need {
        return Err(format!("nothing lit in {at:?}"));
    }
    Ok(probes)
}

/// A line for each probe `want` does not accept the hit of, `what` first.
pub(crate) fn misnamed(
    what: &str,
    (t, lit, at, need): (Table, Table, Rect, bool),
    want: impl Fn(Cell, i32) -> bool,
) -> Vec<String> {
    match probes(t, lit, at, need) {
        Err(e) => vec![format!("{what}: {e}")],
        Ok(ps) => {
            let bad = ps.into_iter().filter(|&(x, y)| !t.hit(at, x, y).is_some_and(|c| want(c, x)));
            bad.map(|(x, y)| format!("{what}: {x},{y} in {at:?} hits {:?}", t.hit(at, x, y)))
                .collect()
        }
    }
}
