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

//! The tab strip and the builders that set it up.

use crate::widgets::State;

/// A row of tabs, one per label, with one selected.
#[derive(Clone, Copy, Debug)]
pub struct Tabs<'a> {
    pub(super) labels: &'a [&'a str],
    pub(super) selected: usize,
    pub(super) hovered: Option<usize>,
    pub(super) state: State,
}

impl<'a> Tabs<'a> {
    /// A strip of `labels` with the tab at `selected` chosen. An index past
    /// the end selects nothing.
    pub fn new(labels: &'a [&'a str], selected: usize) -> Self {
        Tabs { labels, selected, hovered: None, state: State::default() }
    }

    /// The tab under the pointer, if any. It gets a hover wash unless it is
    /// the selected one.
    pub fn hovered(mut self, index: Option<usize>) -> Self {
        self.hovered = index;
        self
    }

    /// The state the app reports for the whole strip. Only `disabled` and
    /// `focused` are read.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }
}
