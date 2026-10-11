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

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::browser::state::State;

pub const MAX_TABS: usize = 6;

/// One page state per tab, boxed: a page's script engine holds a raw
/// pointer into its `page_dom`, which must not move when the list grows or
/// an earlier tab closes.
pub struct Tabs {
    pub list: Vec<Box<State>>,
    pub active: usize,
}

impl Tabs {
    pub fn new() -> Self {
        Tabs { list: vec![Box::new(State::new())], active: 0 }
    }

    pub fn active(&self) -> &State {
        &self.list[self.active]
    }

    pub fn active_mut(&mut self) -> &mut State {
        &mut self.list[self.active]
    }

    /// A blank page with the window's SOCKS proxy and geometry. The
    /// network the reader chose is the window's, and goes with it.
    pub(super) fn fresh(&self) -> Box<State> {
        let cur = self.active();
        let mut s = Box::new(State::new());
        s.proxy = cur.proxy.clone();
        (s.viewport_w, s.viewport_h, s.layout) = (cur.viewport_w, cur.viewport_h, cur.layout);
        s
    }

    pub fn open(&mut self) -> bool {
        if self.list.len() >= MAX_TABS {
            return false;
        }
        let s = self.fresh();
        self.list.push(s);
        self.switch(self.list.len() - 1)
    }
}
