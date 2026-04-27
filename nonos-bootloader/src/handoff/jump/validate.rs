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

const MIN_KERNEL_ADDR: u64 = 0x100000;  // 1MB - below is legacy/BIOS area
const MAX_PHYS_ADDR: u64 = 0x0000_FFFF_FFFF_FFFF;  // 48-bit physical

/// Check if address is canonical (valid in 48-bit virtual address space).
fn is_canonical(addr: u64) -> bool {
    let upper = addr >> 47;
    upper == 0 || upper == 0x1FFFF
}

/// Validate kernel entry point: non-null, above 1MB, canonical, within physical range.
pub fn validate_entry_address(entry: u64) -> bool {
    if entry == 0 || entry < MIN_KERNEL_ADDR { return false; }
    if !is_canonical(entry) { return false; }
    if entry > MAX_PHYS_ADDR { return false; }
    true
}

/// Validate stack address: non-null, above 1MB, canonical, 16-byte aligned per SysV ABI.
pub fn validate_stack_address(stack: u64) -> bool {
    if stack == 0 || stack < MIN_KERNEL_ADDR { return false; }
    if !is_canonical(stack) { return false; }
    if (stack & 0xF) != 0 { return false; }
    if stack > MAX_PHYS_ADDR { return false; }
    true
}

/// Validate handoff struct address: non-null, above 1MB, canonical, 8-byte aligned.
pub fn validate_handoff_address(handoff: u64) -> bool {
    if handoff == 0 || handoff < MIN_KERNEL_ADDR { return false; }
    if !is_canonical(handoff) { return false; }
    if (handoff & 0x7) != 0 { return false; }
    if handoff > MAX_PHYS_ADDR { return false; }
    true
}
