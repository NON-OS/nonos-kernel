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

use super::super::cpu_ops::rdtsc;
use super::super::error::BootError;
use super::super::stage::BootStage;
use super::super::state::{get_boot_tsc, set_complete, set_stage};
use super::super::validation::{enable_sse_avx, validate_memory};
use super::log::{log, log_hex, log_stage};
use super::panic::boot_panic;
use crate::arch::x86_64::{cpu, gdt, idt, vga};

pub unsafe fn boot_late() -> ! {
    set_stage(BootStage::SegmentReload, rdtsc());
    gdt::reload_segments();
    log_stage(BootStage::SegmentReload, true);

    set_stage(BootStage::SseEnable, rdtsc());
    match enable_sse_avx() {
        Ok(()) => {
            log_stage(BootStage::SseEnable, true);
            let f = cpu::features();
            log("  Enabled: SSE SSE2");
            if f.avx {
                log(" AVX");
            }
            if f.avx512f {
                log(" AVX512");
            }
            log("\n");
        }
        Err(e) => {
            log_stage(BootStage::SseEnable, false);
            boot_panic(e);
        }
    }

    set_stage(BootStage::IdtSetup, rdtsc());
    match idt::init() {
        Ok(()) => log_stage(BootStage::IdtSetup, true),
        Err(idt::IdtError::AlreadyInitialized) => log("  IDT already initialized\n"),
        Err(_) => {
            log_stage(BootStage::IdtSetup, false);
            boot_panic(BootError::IdtInitFailed);
        }
    }

    set_stage(BootStage::MemoryValidation, rdtsc());
    match validate_memory() {
        Ok(()) => {
            log_stage(BootStage::MemoryValidation, true);
            log("  Paging/PAE/Long: active\n");
        }
        Err(e) => {
            log_stage(BootStage::MemoryValidation, false);
            boot_panic(e);
        }
    }

    set_stage(BootStage::KernelTransfer, rdtsc());
    log_stage(BootStage::KernelTransfer, true);
    log("\nBoot complete, transferring to kernel_main\n");
    log("================================================================================\n\n");

    set_stage(BootStage::Complete, rdtsc());
    set_complete(true);
    log("Boot duration: ");
    log_hex(rdtsc() - get_boot_tsc());
    log(" TSC ticks\n\n");

    if vga::is_initialized() {
        vga::set_color(vga::Color::LightGreen, vga::Color::Black);
        vga::write_str("\nBoot complete!\n");
        vga::set_color(vga::Color::LightGray, vga::Color::Black);
    }

    crate::entry::kernel_main();
}
