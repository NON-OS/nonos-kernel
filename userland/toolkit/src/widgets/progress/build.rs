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

//! The progress bar and the builders that set it up.

use crate::widgets::{State, Tone};

/// A bar showing `done` out of `total`. Only `State::disabled` is used.
#[derive(Clone, Copy, Debug, Default)]
pub struct Progress {
    pub(super) done: u32,
    pub(super) total: u32,
    pub(super) tone: Tone,
    pub(super) state: State,
}

impl Progress {
    /// A `Plain` bar at `done` out of `total`, with `done` clamped to
    /// `total`. A `total` of 0 is allowed and draws an empty track.
    pub fn new(done: u32, total: u32) -> Self {
        Progress { done: done.min(total), total, tone: Tone::Plain, state: State::default() }
    }

    /// The status the bar shows, which colours the fill. `Plain` fills in
    /// the accent.
    pub fn tone(mut self, tone: Tone) -> Self {
        self.tone = tone;
        self
    }

    /// The state the app reports. Only `disabled` is used.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }
}
