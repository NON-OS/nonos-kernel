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

//! The slider and the builders that set it up.

use crate::widgets::State;

/// A slider showing `value` out of `max`. `State::selected` is ignored.
#[derive(Clone, Copy, Debug, Default)]
pub struct Slider {
    pub(super) value: u32,
    pub(super) max: u32,
    pub(super) state: State,
}

impl Slider {
    /// A slider at `value` out of `max`, with `value` clamped to `max`. A
    /// `max` of 0 is allowed and draws an empty slider.
    pub fn new(value: u32, max: u32) -> Self {
        Slider { value: value.min(max), max, state: State::default() }
    }

    /// The state the app reports. `selected` is ignored.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }
}
