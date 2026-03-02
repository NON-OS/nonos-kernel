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

use super::*;

#[test]
fn context_layout_is_stable() {
    // Basic sanity: all fields are 64-bit, count matches.
    // 6 callee-saved + 3 control + 2 segments = 11 u64s
    let expected_size = core::mem::size_of::<u64>() * 11;
    assert_eq!(core::mem::size_of::<CpuContext>(), expected_size);
    assert_eq!(
        core::mem::align_of::<CpuContext>(),
        core::mem::align_of::<u64>()
    );
}

#[test]
fn prepare_user_entry_sets_reserved_flag() {
    let mut ctx = CpuContext::new();
    ctx.prepare_user_entry(0x401000, 0x7fff_ffff_f000, 0x1b, 0x23, 0x202);
    assert_eq!(ctx.rip, 0x401000);
    assert_eq!(ctx.rsp, 0x7fff_ffff_f000);
    assert_eq!(ctx.cs, 0x1b);
    assert_eq!(ctx.ss, 0x23);
    // Bit 1 must always be set
    assert_ne!(ctx.rflags & (1 << 1), 0);
}

#[test]
fn prepare_kernel_entry_sets_reserved_flag() {
    let mut ctx = CpuContext::new();
    ctx.prepare_kernel_entry(0xdead_beef, 0xffff_ffff_ffff_f000, 0x200);
    assert_eq!(ctx.rip, 0xdead_beef);
    assert_eq!(ctx.rsp, 0xffff_ffff_ffff_f000);
    assert_ne!(ctx.rflags & (1 << 1), 0);
}
