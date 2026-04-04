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

use super::definition::Context;
use core::sync::atomic::{AtomicBool, Ordering};

pub(crate) static CONTEXT_JUST_RESTORED: AtomicBool = AtomicBool::new(false);

impl Context {
    #[inline(always)]
    pub fn save() -> Self {
        let mut ctx: Context = unsafe { core::mem::zeroed() };
        unsafe {
            core::arch::asm!(
                "mov [{0}], rax",
                "mov [{0} + 8], rbx",
                "mov [{0} + 16], rcx",
                "mov [{0} + 24], rdx",
                "mov [{0} + 32], rsi",
                "mov [{0} + 40], rdi",
                "mov [{0} + 48], rbp",
                "mov [{0} + 56], rsp",
                "mov [{0} + 64], r8",
                "mov [{0} + 72], r9",
                "mov [{0} + 80], r10",
                "mov [{0} + 88], r11",
                "mov [{0} + 96], r12",
                "mov [{0} + 104], r13",
                "mov [{0} + 112], r14",
                "mov [{0} + 120], r15",
                "pushfq",
                "pop rax",
                "mov [{0} + 136], rax",
                "lea rax, [rip + 2f]",
                "mov [{0} + 128], rax",
                "2:",
                in(reg) &mut ctx as *mut Context,
                out("rax") _,
            );
        }
        ctx
    }

    pub fn was_just_restored() -> bool {
        CONTEXT_JUST_RESTORED.swap(false, Ordering::SeqCst)
    }

    pub fn clear_restored_flag() {
        CONTEXT_JUST_RESTORED.store(false, Ordering::SeqCst);
    }
}
