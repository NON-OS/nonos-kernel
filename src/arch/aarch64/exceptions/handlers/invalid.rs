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

use crate::arch::aarch64::exceptions::frame::ExceptionFrame;

use super::fatal::fatal;

// Current EL with SP_EL0. NONOS runs the kernel on SPx; entry through
// SP0 vectors is a stack-selection bug.
#[no_mangle]
pub extern "C" fn aarch64_exc_invalid_sp0(frame: *mut ExceptionFrame) -> ! {
    // SAFETY: frame is the kernel-stack frame built by vectors.S.
    let frame = unsafe { &*frame };
    fatal(b"SP_EL0 vector", frame)
}

// Lower EL using AArch32. AArch32 user execution is not supported.
#[no_mangle]
pub extern "C" fn aarch64_exc_invalid_aarch32(frame: *mut ExceptionFrame) -> ! {
    // SAFETY: frame is the kernel-stack frame built by vectors.S.
    let frame = unsafe { &*frame };
    fatal(b"AArch32 vector", frame)
}
