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

use super::supervision::supervise_services;
use super::verification::verify_services;

const VERIFY_INTERVAL_MS: u64 = 5000;
const SUPERVISE_INTERVAL_MS: u64 = 1000;

pub(crate) fn init_loop() -> ! {
    let mut last_verify = 0u64;
    let mut last_supervise = 0u64;
    loop {
        let now = crate::time::timestamp_millis();
        if now >= last_verify + VERIFY_INTERVAL_MS {
            verify_services();
            last_verify = now;
        }
        if now >= last_supervise + SUPERVISE_INTERVAL_MS {
            supervise_services();
            last_supervise = now;
        }
        crate::sched::yield_now();
    }
}
