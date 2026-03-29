// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::super::jump::entry::{
    jump_to_kernel, validate_entry_address, validate_handoff_address, validate_stack_address,
};
use crate::log::logger::log_error;

pub struct JumpAddresses {
    pub entry: u64,
    pub stack: u64,
    pub handoff: u64,
}

pub fn validate_and_jump(addrs: JumpAddresses) -> ! {
    if !validate_entry_address(addrs.entry) {
        log_error("handoff", "invalid kernel entry address");
        halt_loop();
    }

    if !validate_stack_address(addrs.stack) {
        log_error("handoff", "invalid stack address");
        halt_loop();
    }

    if !validate_handoff_address(addrs.handoff) {
        log_error("handoff", "invalid handoff address");
        halt_loop();
    }

    unsafe { jump_to_kernel(addrs.entry, addrs.stack, addrs.handoff) }
}

fn halt_loop() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
