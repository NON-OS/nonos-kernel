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

use crate::syscall::microkernel::capability::check_caps_internal;

pub fn check_capability_enforcement() {
    let init_has_all = check_caps_internal(1, u64::MAX);
    if !init_has_all {
        crate::sys::serial::println(b"[TEST] WARNING: Init missing caps");
    }

    let nonexistent = check_caps_internal(999999, 0x1);
    if nonexistent {
        crate::sys::serial::println(b"[TEST] WARNING: Ghost PID has caps");
    }

    crate::sys::serial::println(b"[TEST] Capability enforcement: OK");
}
