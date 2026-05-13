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

use super::info::BootInfo;

// `_start` and BSS clearing live in arch/aarch64/asm/start.S; that asm
// drops to EL1 if entered at EL2, preserves x0 = dtb_ptr across the
// drop, and tail-calls this function.

#[no_mangle]
pub extern "C" fn kernel_entry(dtb_ptr: u64) -> ! {
    let mut info = BootInfo::default();
    // dtb_adapter::populate returns false on bad magic/version; we
    // keep the defaults but leave dtb_base = 0 to signal "no DTB
    // consumed" so downstream code can tell the difference.
    super::dtb_adapter::populate(dtb_ptr, &mut info);

    super::init(&info);

    crate::kernel_main();
}
