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

use super::cpuid;
use super::msr::{rdmsr, wrmsr};
use super::constants::{MSR_IA32_SPEC_CTRL, SPEC_CTRL_SSBD};

#[inline(always)]
pub fn ssbd_enable() {
    if cpuid::has_ssbd() {
        // SAFETY: SSBD MSR access is valid when SSBD feature is supported.
        let current = unsafe { rdmsr(MSR_IA32_SPEC_CTRL) };
        unsafe { wrmsr(MSR_IA32_SPEC_CTRL, current | SPEC_CTRL_SSBD); }
    }
}

#[inline(always)]
pub fn ssbd_disable() {
    if cpuid::has_ssbd() {
        // SAFETY: SSBD MSR access is valid when SSBD feature is supported.
        let current = unsafe { rdmsr(MSR_IA32_SPEC_CTRL) };
        unsafe { wrmsr(MSR_IA32_SPEC_CTRL, current & !SPEC_CTRL_SSBD); }
    }
}
