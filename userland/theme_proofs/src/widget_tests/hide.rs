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

//! The marks a `Masked` surface can leave out.

/// The mark left out.
#[derive(Clone, Copy)]
pub(crate) enum Hide {
    /// A run of text: this one, or a cut of it with `…` at either end.
    Text(&'static str),
    /// Every run that is a piece of this one, such as each line it wraps
    /// to, whole or cut with `…` at its end.
    Within(&'static str),
    /// Every filled circle.
    Dots,
    /// Every icon.
    Icons,
    /// The filled rounded rect painted `n`th, counting from 0.
    Round(u32),
}

impl Hide {
    /// Whether `drawn`, a run of text, is the one left out.
    pub(crate) fn text(self, drawn: &str) -> bool {
        if let Hide::Within(run) = self {
            return run.contains(drawn.strip_suffix('…').unwrap_or(drawn));
        }
        let Hide::Text(run) = self else { return false };
        let head = drawn.strip_suffix('…').is_some_and(|s| run.starts_with(s));
        drawn == run || head || drawn.strip_prefix('…').is_some_and(|s| run.ends_with(s))
    }
}
