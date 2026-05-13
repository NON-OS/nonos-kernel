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

// 0 means unset. The BSP boot path calls `configure` once the DTB
// adapter has resolved the intid; every AP then reads the same value
// during its own `install_on_cpu`. Atomic because reads happen from
// many CPUs after the BSP has published.
static PHYS_INTID: AtomicU32 = AtomicU32::new(0);

pub fn configure(intid: u32) {
    PHYS_INTID.store(intid, Ordering::Release);
}

pub fn phys_intid() -> u32 {
    PHYS_INTID.load(Ordering::Acquire)
}
