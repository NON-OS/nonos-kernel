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

use super::constants::*;
use super::state::wrmsr;

pub(super) fn init_x2apic() {
    let svr = SVR_APIC_ENABLE as u64 | VEC_SPURIOUS as u64 | SVR_EOI_SUPPRESS as u64;
    wrmsr(IA32_X2APIC_SVR, svr);
    wrmsr(IA32_X2APIC_LVT_LINT0, LVT_NMI as u64);
    wrmsr(IA32_X2APIC_LVT_LINT1, LVT_MASKED as u64);
    wrmsr(IA32_X2APIC_LVT_THERM, LVT_FIXED as u64 | VEC_THERMAL as u64);
    wrmsr(IA32_X2APIC_LVT_ERROR, LVT_FIXED as u64 | VEC_ERROR as u64);
    wrmsr(IA32_X2APIC_LVT_TIMER, LVT_MASKED as u64);
}
