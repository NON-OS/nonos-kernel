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

use crate::arch::aarch64::cpu;
use crate::arch::aarch64::exceptions::frame::ExceptionFrame;
use crate::sys::serial;

// Log the tag, dump the frame, halt this CPU. Mask DAIF first so the
// dump cannot be re-entered by an asynchronous exception.
pub fn fatal(tag: &[u8], frame: &ExceptionFrame) -> ! {
    // SAFETY: tightening DAIF cannot fault on a valid CPU.
    unsafe {
        core::arch::asm!("msr daifset, #0xf", options(nostack));
    }
    serial::print(b"[aarch64] fatal: ");
    serial::println(tag);
    frame.dump();
    cpu::halt()
}
