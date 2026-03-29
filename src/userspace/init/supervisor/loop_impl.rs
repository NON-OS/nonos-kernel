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

use super::verification::verify_services;
use super::supervision::supervise_services;

pub(crate) fn init_loop() -> ! {
    crate::sys::serial::println(b"[INIT] Init entering supervision loop");
    let mut verify_count = 0u32;
    loop {
        if verify_count < 3 {
            verify_services();
            verify_count += 1;
        }
        supervise_services();
        crate::sched::yield_now();
    }
}
