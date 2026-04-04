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

use crate::sys::settings::api::kernel as ks;

pub(crate) fn handle_click(cx: u32, cy: u32, cw: u32, mx: i32, my: i32) -> bool {
    let toggle_x = cx + cw - 80;
    let rows: [(u32, fn() -> bool, fn(bool)); 12] = [
        (cy + 32, ks::kernel_aslr, ks::set_kernel_aslr),
        (cy + 56, ks::kernel_stack_guard, ks::set_kernel_stack_guard),
        (cy + 80, ks::kernel_nx_bit, ks::set_kernel_nx_bit),
        (cy + 104, ks::kernel_smep, ks::set_kernel_smep),
        (cy + 128, ks::kernel_smap, ks::set_kernel_smap),
        (cy + 202, ks::kernel_preempt, ks::set_kernel_preempt),
        (cy + 226, ks::kernel_hugepages, ks::set_kernel_hugepages),
        (cy + 250, ks::kernel_iommu, ks::set_kernel_iommu),
        (cy + 322, ks::kernel_debug, ks::set_kernel_debug),
        (cy + 346, ks::kernel_serial, ks::set_kernel_serial),
        (cy + 370, ks::kernel_watchdog, ks::set_kernel_watchdog),
        (cy + 442, ks::kernel_seccomp, ks::set_kernel_seccomp),
    ];
    for (row_y, getter, setter) in rows {
        if my >= (row_y - 4) as i32 && my < (row_y + 22) as i32 {
            if mx >= toggle_x as i32 && mx < (toggle_x + 50) as i32 {
                setter(!getter());
                return true;
            }
        }
    }
    false
}
