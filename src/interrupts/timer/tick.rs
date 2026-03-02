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

use super::hooks;
use super::state;

pub fn on_timer_interrupt() {
    state::increment_ticks();
    crate::network::network_tick();

    if state::get_ticks() % 10 == 0 {
        crate::arch::x86_64::syscall::handlers::time::check_alarms();
    }

    hooks::invoke_hook();
}

pub fn tick() {
    on_timer_interrupt();
}
