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

use super::types::SavedUser;

extern "C" {
    fn aarch64_resume_user(saved: *const SavedUser) -> !;
}

#[derive(Debug, Clone, Copy)]
pub enum ResumeError {
    NoKernelStack,
    NotFromEl0,
}

// Resume an EL0 task from a captured preempt snapshot. `saved.spsr_el1`
// must reflect a return to EL0t (M[3:0] = 0); refusing otherwise stops
// a resume hook from accidentally eret'ing into EL1 with user-controlled
// registers. Caller has already swapped CR3-equivalent (TTBR0) and
// masked IRQs.
pub unsafe fn resume_user(saved: &SavedUser) -> Result<core::convert::Infallible, ResumeError> {
    if saved.kernel_sp == 0 {
        return Err(ResumeError::NoKernelStack);
    }
    if (saved.spsr_el1 & 0xf) != 0 {
        return Err(ResumeError::NotFromEl0);
    }
    unsafe { aarch64_resume_user(saved as *const _) }
}
