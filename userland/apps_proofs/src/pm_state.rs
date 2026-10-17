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

//! The parts of the process monitor's state its hit test and hover read,
//! standing in for the capsule's `State`, which holds syscall handles and
//! kernel records the host does not have.

use alloc::vec::Vec;

use nonos_toolkit::widgets::Pointer;

use crate::pm::state::{Filter, Screen};
use crate::pm::ui::hit::Target;

/// A process as the filters read it: its pid, its authority and its name.
pub struct Row {
    pub pid: u32,
    pub caps: u64,
    pub name: &'static [u8],
}

impl Row {
    pub fn name(&self) -> &[u8] {
        self.name
    }
}

/// The rows, the filter over them, the scrolls, the screen on show and the
/// surface's size; and the pointer and its hover, so a proof can show that
/// setting the hover moves nothing. No query is typed, so every name matches it.
pub struct State {
    pub rows: Vec<Row>,
    pub filter: Filter,
    pub flagged: Vec<u32>,
    pub me: u32,
    pub selected_pid: u32,
    pub scroll: usize,
    pub screen: Screen,
    pub alerts: Vec<()>,
    pub alert_scroll: usize,
    pub fb_w: u32,
    pub fb_h: u32,
    pub pointer: Pointer,
    pub hover: Option<Target>,
}

impl State {
    pub fn query_matches(&self, _name: &[u8]) -> bool {
        true
    }

    pub fn query_focused(&self) -> bool {
        false
    }

    pub fn query(&self) -> &[u8] {
        b""
    }
}
