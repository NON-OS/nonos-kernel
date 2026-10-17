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

use alloc::vec::Vec;

use super::super::security::Monitor;
use super::notes;
use super::{Filter, History, Query, Screen, Sort, State};

impl State {
    pub fn new() -> Self {
        let mut state = State {
            rows: Vec::new(),
            sys: super::System::default(),
            refreshes: 0,
            status: notes::READING,
            selected_pid: 0,
            notice: b"",
            pending_pid: 0,
            me: nonos_libc::mk_getpid(),
            sort: Sort::Cpu,
            scroll: 0,
            visible: 1,
            fb_w: 0,
            fb_h: 0,
            total_mem_kb: 0,
            total_cpu: 0,
            last_total_ticks: 0,
            prev: Vec::new(),
            history: History::new(),
            filter: Filter::All,
            query: Query::new(),
            screen: Screen::Overview,
            help_open: false,
            monitor: Monitor::new(),
            alerts: Vec::new(),
            flagged: Vec::new(),
            alert_sel: 0,
            alert_scroll: 0,
            alert_visible: 1,
            pointer: nonos_toolkit::widgets::Pointer::new(),
            hover: None,
        };
        state.refresh();
        state
    }
}
