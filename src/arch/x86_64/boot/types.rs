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

use super::stage::BootStage;

pub use crate::arch::x86_64::cpu::CpuFeatures;
pub use crate::arch::x86_64::gdt::Tss;
pub use crate::arch::x86_64::idt::InterruptFrame;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExceptionContext {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl ExceptionContext {
    pub fn instruction_pointer(&self) -> u64 {
        self.rip
    }

    pub fn stack_pointer(&self) -> u64 {
        self.rsp
    }

    pub fn code_segment(&self) -> u64 {
        self.cs
    }

    pub fn is_user_mode(&self) -> bool {
        (self.cs & 3) == 3
    }

    pub fn is_kernel_mode(&self) -> bool {
        (self.cs & 3) == 0
    }

    pub fn has_error_code(&self) -> bool {
        matches!(
            self.vector,
            8 | 10 | 11 | 12 | 13 | 14 | 17 | 21 | 29 | 30
        )
    }
}

impl Default for ExceptionContext {
    fn default() -> Self {
        Self {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rbp: 0,
            rdi: 0,
            rsi: 0,
            rdx: 0,
            rcx: 0,
            rbx: 0,
            rax: 0,
            vector: 0,
            error_code: 0,
            rip: 0,
            cs: 0,
            rflags: 0,
            rsp: 0,
            ss: 0,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct BootStats {
    pub stage: u8,
    pub error: u8,
    pub complete: bool,
    pub boot_tsc: u64,
    pub complete_tsc: u64,
    pub exceptions: u64,
    pub stage_tsc: [u64; BootStage::COUNT],
}

impl BootStats {
    pub fn duration_tsc(&self) -> u64 {
        if self.complete_tsc > self.boot_tsc {
            self.complete_tsc - self.boot_tsc
        } else {
            0
        }
    }

    pub fn stage_duration(&self, stage: BootStage) -> u64 {
        let idx = stage.as_u8() as usize;
        if idx == 0 {
            return 0;
        }
        if idx >= BootStage::COUNT {
            return 0;
        }

        let current = self.stage_tsc[idx];
        let prev = self.stage_tsc[idx - 1];

        if current > prev {
            current - prev
        } else {
            0
        }
    }

    pub fn current_stage(&self) -> BootStage {
        BootStage::from_u8(self.stage)
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn has_error(&self) -> bool {
        self.error != 0
    }
}

impl core::fmt::Debug for BootStats {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BootStats")
            .field("stage", &BootStage::from_u8(self.stage))
            .field("error", &self.error)
            .field("complete", &self.complete)
            .field("duration_tsc", &self.duration_tsc())
            .field("exceptions", &self.exceptions)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_stats_duration() {
        let stats = BootStats {
            boot_tsc: 1000,
            complete_tsc: 5000,
            ..Default::default()
        };
        assert_eq!(stats.duration_tsc(), 4000);
    }

    #[test]
    fn test_boot_stats_duration_zero() {
        let stats = BootStats::default();
        assert_eq!(stats.duration_tsc(), 0);
    }

    #[test]
    fn test_exception_context_default() {
        let ctx = ExceptionContext::default();
        assert_eq!(ctx.rip, 0);
        assert_eq!(ctx.vector, 0);
    }

    #[test]
    fn test_exception_context_privilege() {
        let mut ctx = ExceptionContext::default();
        ctx.cs = 0x08;
        assert!(ctx.is_kernel_mode());
        assert!(!ctx.is_user_mode());

        ctx.cs = 0x1B;
        assert!(!ctx.is_kernel_mode());
        assert!(ctx.is_user_mode());
    }

    #[test]
    fn test_has_error_code() {
        let mut ctx = ExceptionContext::default();

        ctx.vector = 14;
        assert!(ctx.has_error_code());

        ctx.vector = 0;
        assert!(!ctx.has_error_code());

        ctx.vector = 13;
        assert!(ctx.has_error_code());
    }
}
