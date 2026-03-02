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

mod counters;
mod query;

pub use counters::{
    increment_exceptions, increment_keyboard, increment_mouse, increment_page_faults,
    increment_syscalls, increment_timer, InterruptCounters, COUNTERS,
};
pub use query::{get_stats, get_stats_tuple, reset_stats, InterruptStats};
