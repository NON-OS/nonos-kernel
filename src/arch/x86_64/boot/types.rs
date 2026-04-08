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

pub use super::types_context::ExceptionContext;
pub use super::types_stats::BootStats;
pub use crate::arch::x86_64::cpu::CpuFeatures;
pub use crate::arch::x86_64::gdt::Tss;
pub use crate::arch::x86_64::idt::InterruptFrame;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_stats_duration() {
        let stats = BootStats { boot_tsc: 1000, complete_tsc: 5000, ..Default::default() };
        assert_eq!(stats.duration_tsc(), 4000);
    }

    #[test]
    fn test_exception_context_default() {
        let ctx = ExceptionContext::default();
        assert_eq!(ctx.rip, 0);
    }

    #[test]
    fn test_exception_context_privilege() {
        let mut ctx = ExceptionContext::default();
        ctx.cs = 0x08;
        assert!(ctx.is_kernel_mode());
        ctx.cs = 0x1B;
        assert!(ctx.is_user_mode());
    }
}
