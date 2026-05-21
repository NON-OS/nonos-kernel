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

extern "C" {
    pub(in crate::smp::trampoline) static nonos_ap_trampoline_start: u8;
    pub(in crate::smp::trampoline) static nonos_ap_trampoline_end: u8;
    pub(in crate::smp::trampoline) static nonos_ap_trampoline_pml4: u8;
    pub(in crate::smp::trampoline) static nonos_ap_trampoline_stack: u8;
    pub(in crate::smp::trampoline) static nonos_ap_trampoline_entry: u8;
    pub(in crate::smp::trampoline) static nonos_ap_trampoline_cpu_id: u8;
    pub(in crate::smp::trampoline) static nonos_ap_trampoline_ready: u8;
}
