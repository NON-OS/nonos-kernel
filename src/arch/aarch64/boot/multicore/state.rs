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

use core::sync::atomic::{AtomicU32, Ordering};

pub(super) static CPUS_ONLINE: AtomicU32 = AtomicU32::new(1);

pub fn online_cpu_count() -> u32 {
    CPUS_ONLINE.load(Ordering::Acquire)
}

pub fn is_cpu_online(cpu: u32) -> bool {
    cpu < CPUS_ONLINE.load(Ordering::Acquire)
}

pub fn wait_for_cpus(count: u32) {
    while CPUS_ONLINE.load(Ordering::Acquire) < count {
        core::hint::spin_loop();
    }
}
