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

// We're past the CR3 swap. Everything below is a VA in the new
// address space. Entry sits in the upper half; stack and handoff
// arrive as directmap virts. A 48-bit phys ceiling makes no sense
// here; canonical-VA + alignment is the right invariant.

const MIN_KERNEL_ADDR: u64 = 0x100000;

// Canonical x86_64 VA: top 17 bits all 0 or all 1.
fn is_canonical(addr: u64) -> bool {
    let upper = addr >> 47;
    upper == 0 || upper == 0x1FFFF
}

pub fn validate_entry_address(entry: u64) -> bool {
    if entry == 0 || entry < MIN_KERNEL_ADDR {
        return false;
    }
    is_canonical(entry)
}

pub fn validate_stack_address(stack: u64) -> bool {
    if stack == 0 || stack < MIN_KERNEL_ADDR {
        return false;
    }
    if (stack & 0xF) != 0 {
        return false;
    }
    is_canonical(stack)
}

pub fn validate_handoff_address(handoff: u64) -> bool {
    if handoff == 0 || handoff < MIN_KERNEL_ADDR {
        return false;
    }
    if (handoff & 0x7) != 0 {
        return false;
    }
    is_canonical(handoff)
}
