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

//! The scroll bar and the builders that set it up.

use crate::widgets::State;

/// A scroll bar for `content` pixels seen through a `viewport`, scrolled
/// down by `offset`. `selected` and `focused` are ignored.
#[derive(Clone, Copy, Debug, Default)]
pub struct Scrollbar {
    pub(super) offset: u32,
    pub(super) content: u32,
    pub(super) viewport: u32,
    pub(super) state: State,
}

impl Scrollbar {
    /// A bar at `offset`, clamped to `content - viewport`, for `content`
    /// seen through `viewport`. Any unit works, so long as all three match.
    pub fn new(offset: u32, content: u32, viewport: u32) -> Self {
        let offset = offset.min(content.saturating_sub(viewport));
        Scrollbar { offset, content, viewport, state: State::default() }
    }

    /// The state the app reports. `selected` and `focused` are ignored.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }
}
