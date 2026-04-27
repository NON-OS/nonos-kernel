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

use crate::sched::*;
use crate::test::framework::TestResult;

fn create_context(rip: u64, rsp: u64) -> Context {
    Context {
        rax: 0,
        rbx: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        rbp: 0,
        rsp,
        r8: 0,
        r9: 0,
        r10: 0,
        r11: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rip,
        rflags: 0,
    }
}

pub(crate) fn test_context_struct_size() -> TestResult {
    if core::mem::size_of::<Context>() != 18 * 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_is_repr_c() -> TestResult {
    let ctx = create_context(0x1000, 0x2000);
    let ptr = &ctx as *const Context as *const u64;
    unsafe {
        if *ptr != ctx.rax {
            return TestResult::Fail;
        }
        if *ptr.add(1) != ctx.rbx {
            return TestResult::Fail;
        }
        if *ptr.add(7) != ctx.rsp {
            return TestResult::Fail;
        }
        if *ptr.add(16) != ctx.rip {
            return TestResult::Fail;
        }
        if *ptr.add(17) != ctx.rflags {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_context_copy() -> TestResult {
    let ctx1 = create_context(0x1000, 0x2000);
    let ctx2 = ctx1;
    if ctx1.rip != ctx2.rip {
        return TestResult::Fail;
    }
    if ctx1.rsp != ctx2.rsp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_clone() -> TestResult {
    let ctx1 = create_context(0x1000, 0x2000);
    let ctx2 = ctx1.clone();
    if ctx1.rip != ctx2.rip {
        return TestResult::Fail;
    }
    if ctx1.rsp != ctx2.rsp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_validate_valid_kernel() -> TestResult {
    let ctx = create_context(0xFFFF_8000_0000_1000, 0xFFFF_8000_0000_2000);
    if ctx.validate().is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_validate_valid_userspace() -> TestResult {
    let ctx = create_context(0x0000_0000_0040_0000, 0x0000_7FFF_FFFF_0000);
    if ctx.validate().is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_validate_noncanonical_rip() -> TestResult {
    let ctx = create_context(0x0000_8000_0000_0000, 0x0000_0000_0040_0000);
    if ctx.validate().is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_validate_noncanonical_rsp() -> TestResult {
    let ctx = create_context(0x0000_0000_0040_0000, 0x0000_8000_0000_0000);
    if ctx.validate().is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_validate_null_rsp() -> TestResult {
    let ctx = create_context(0x0000_0000_0040_0000, 0);
    if ctx.validate().is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_validate_userspace_valid() -> TestResult {
    let ctx = create_context(0x0000_0000_0040_0000, 0x0000_7FFF_0000_0000);
    if ctx.validate_userspace().is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_validate_userspace_kernel_rip() -> TestResult {
    let ctx = create_context(0xFFFF_8000_0000_1000, 0x0000_7FFF_0000_0000);
    if ctx.validate_userspace().is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_validate_userspace_kernel_rsp() -> TestResult {
    let ctx = create_context(0x0000_0000_0040_0000, 0xFFFF_8000_0000_2000);
    if ctx.validate_userspace().is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_validate_userspace_boundary_rip() -> TestResult {
    let ctx = create_context(0x0000_7FFF_FFFF_FFFF, 0x0000_7FFF_0000_0000);
    if ctx.validate_userspace().is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_validate_userspace_over_boundary_rip() -> TestResult {
    let ctx = create_context(0x0000_8000_0000_0000, 0x0000_7FFF_0000_0000);
    if ctx.validate_userspace().is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_all_registers_zero() -> TestResult {
    let ctx = create_context(0x1000, 0x2000);
    if ctx.rax != 0 {
        return TestResult::Fail;
    }
    if ctx.rbx != 0 {
        return TestResult::Fail;
    }
    if ctx.rcx != 0 {
        return TestResult::Fail;
    }
    if ctx.rdx != 0 {
        return TestResult::Fail;
    }
    if ctx.rsi != 0 {
        return TestResult::Fail;
    }
    if ctx.rdi != 0 {
        return TestResult::Fail;
    }
    if ctx.rbp != 0 {
        return TestResult::Fail;
    }
    if ctx.r8 != 0 {
        return TestResult::Fail;
    }
    if ctx.r9 != 0 {
        return TestResult::Fail;
    }
    if ctx.r10 != 0 {
        return TestResult::Fail;
    }
    if ctx.r11 != 0 {
        return TestResult::Fail;
    }
    if ctx.r12 != 0 {
        return TestResult::Fail;
    }
    if ctx.r13 != 0 {
        return TestResult::Fail;
    }
    if ctx.r14 != 0 {
        return TestResult::Fail;
    }
    if ctx.r15 != 0 {
        return TestResult::Fail;
    }
    if ctx.rflags != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_with_custom_registers() -> TestResult {
    let ctx = Context {
        rax: 1,
        rbx: 2,
        rcx: 3,
        rdx: 4,
        rsi: 5,
        rdi: 6,
        rbp: 7,
        rsp: 0x2000,
        r8: 8,
        r9: 9,
        r10: 10,
        r11: 11,
        r12: 12,
        r13: 13,
        r14: 14,
        r15: 15,
        rip: 0x1000,
        rflags: 0x202,
    };

    if ctx.rax != 1 {
        return TestResult::Fail;
    }
    if ctx.r8 != 8 {
        return TestResult::Fail;
    }
    if ctx.r15 != 15 {
        return TestResult::Fail;
    }
    if ctx.rflags != 0x202 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_canonical_boundary_low() -> TestResult {
    let ctx = create_context(0x0000_7FFF_FFFF_FFFF, 0x1000);
    if ctx.validate().is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_canonical_boundary_high() -> TestResult {
    let ctx = create_context(0xFFFF_8000_0000_0000, 0xFFFF_8000_0000_1000);
    if ctx.validate().is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_noncanonical_hole_low() -> TestResult {
    let ctx = create_context(0x0000_8000_0000_0000, 0x1000);
    if ctx.validate().is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_noncanonical_hole_high() -> TestResult {
    let ctx = create_context(0xFFFF_7FFF_FFFF_FFFF, 0x1000);
    if ctx.validate().is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
