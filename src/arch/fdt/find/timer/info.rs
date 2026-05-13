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

// Intids resolved from the architected-timer node. Zero means the
// corresponding variant was not present in the DTB. EL1 kernels use
// `nonsecure_phys_intid` (CNTP_*_EL0) unless explicitly running under
// a hypervisor that exposes only the virtual timer.
#[derive(Debug, Clone, Copy, Default)]
pub struct TimerInfo {
    pub nonsecure_phys_intid: u32,
    pub virtual_intid: u32,
    pub hyp_phys_intid: u32,
    pub secure_phys_intid: u32,
}
