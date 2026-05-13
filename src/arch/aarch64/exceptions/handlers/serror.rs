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

// SError is an asynchronous external abort. Almost always indicates an
// uncorrected hardware error; not recoverable here.
#[no_mangle]
pub extern "C" fn aarch64_exc_serror_current(frame: *mut ExceptionFrame) -> ! {
    // SAFETY: frame is the kernel-stack frame built by vectors.S.
    let frame = unsafe { &*frame };
    fatal(b"SError EL1", frame)
}

#[no_mangle]
pub extern "C" fn aarch64_exc_serror_lower(frame: *mut ExceptionFrame) -> ! {
    // SAFETY: frame is the kernel-stack frame built by vectors.S.
    let frame = unsafe { &*frame };
    fatal(b"SError EL0", frame)
}
