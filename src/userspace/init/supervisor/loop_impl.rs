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

//! Init's residual loop after every capsule has been spawned. Walks
//! the lifecycle registry once per second; any capsule that exited is
//! observed `Dead` on its next IPC. The kernel does not actively
//! probe capsules — liveness arrives through the existing process
//! state machine.

const TICK_INTERVAL_MS: u64 = 1000;

pub(crate) fn init_loop() -> ! {
    let mut last_tick = 0u64;
    loop {
        let now = crate::time::timestamp_millis();
        if now >= last_tick + TICK_INTERVAL_MS {
            crate::services::lifecycle::tick();
            last_tick = now;
        }
        crate::sched::yield_now();
    }
}
