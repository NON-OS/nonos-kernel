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

use core::arch::asm;

use super::super::constants::BOOT_STACK_TOP;
use super::super::cpu_ops::rdtsc;
use super::super::error::BootError;
use super::super::stage::BootStage;
use super::super::state::{set_boot_tsc, set_complete, set_stage};
use super::super::validation::{enable_sse_avx, validate_cpu_features, validate_memory};
use super::log::{log, log_hex, log_stage};
use super::panic::boot_panic;

use crate::arch::x86_64::{cpu, gdt, idt, serial, vga};

#[cfg(not(feature = "std"))]
#[no_mangle]
#[link_section = ".text.boot"]
pub unsafe extern "C" fn _arch_start() -> ! {
    asm!(
        "mov rsp, {}",
        "mov rbp, rsp",
        "xor rbp, rbp",
        "call {}",
        in(reg) BOOT_STACK_TOP,
        sym boot_main,
        options(noreturn)
    );
}

#[no_mangle]
pub unsafe extern "C" fn boot_main() -> ! {
    set_boot_tsc(rdtsc());

    set_stage(BootStage::Entry, rdtsc());

    set_stage(BootStage::SerialInit, rdtsc());
    match serial::init() {
        Ok(()) => {
            log("\n");
            log("================================================================================\n");
            log("                           NONOS x86_64 Boot                                   \n");
            log("================================================================================\n");
            log("\n");
            log_stage(BootStage::SerialInit, true);
        }
        Err(_) => {}
    }

    set_stage(BootStage::VgaInit, rdtsc());
    match vga::init() {
        Ok(()) => {
            vga::clear();
            vga::set_color(vga::Color::White, vga::Color::Blue);
            vga::write_str(" NONOS x86_64 Boot ");
            vga::set_color(vga::Color::LightGray, vga::Color::Black);
            vga::write_str("\n\n");
            log_stage(BootStage::VgaInit, true);
        }
        Err(_) => {
            log_stage(BootStage::VgaInit, false);
        }
    }

    set_stage(BootStage::CpuDetect, rdtsc());
    match cpu::init() {
        Ok(()) => {
            log_stage(BootStage::CpuDetect, true);

            let features = cpu::features();
            let vendor = cpu::vendor();

            log("  Vendor: ");
            match vendor {
                cpu::CpuVendor::Intel => log("Intel"),
                cpu::CpuVendor::Amd => log("AMD"),
                _ => log("Other"),
            }
            log("\n");

            log("  Features:");
            if features.sse { log(" SSE"); }
            if features.sse2 { log(" SSE2"); }
            if features.sse3 { log(" SSE3"); }
            if features.avx { log(" AVX"); }
            if features.avx2 { log(" AVX2"); }
            if features.avx512f { log(" AVX512F"); }
            if features.aes_ni { log(" AES"); }
            log("\n");

            if vga::is_initialized() {
                vga::write_str("CPU: ");
                match vendor {
                    cpu::CpuVendor::Intel => vga::write_str("Intel"),
                    cpu::CpuVendor::Amd => vga::write_str("AMD"),
                    _ => vga::write_str("Other"),
                }
                vga::write_str("\n");
            }
        }
        Err(e) => {
            log_stage(BootStage::CpuDetect, false);
            match e {
                cpu::CpuError::NoCpuid => boot_panic(BootError::NoCpuid),
                cpu::CpuError::NoLongMode => boot_panic(BootError::NoLongMode),
                _ => boot_panic(BootError::CpuInitFailed),
            }
        }
    }

    if let Err(e) = validate_cpu_features() {
        boot_panic(e);
    }

    set_stage(BootStage::GdtSetup, rdtsc());
    match gdt::init() {
        Ok(()) => {
            log_stage(BootStage::GdtSetup, true);
        }
        Err(e) => {
            log_stage(BootStage::GdtSetup, false);
            match e {
                gdt::GdtError::AlreadyInitialized => {
                    log("  GDT already initialized\n");
                }
                _ => boot_panic(BootError::GdtInitFailed),
            }
        }
    }

    set_stage(BootStage::SegmentReload, rdtsc());
    gdt::reload_segments();
    log_stage(BootStage::SegmentReload, true);

    set_stage(BootStage::SseEnable, rdtsc());
    match enable_sse_avx() {
        Ok(()) => {
            log_stage(BootStage::SseEnable, true);

            let features = cpu::features();
            log("  Enabled:");
            log(" SSE SSE2");
            if features.avx { log(" AVX"); }
            if features.avx512f { log(" AVX512"); }
            log("\n");
        }
        Err(e) => {
            log_stage(BootStage::SseEnable, false);
            boot_panic(e);
        }
    }

    set_stage(BootStage::IdtSetup, rdtsc());
    match idt::init() {
        Ok(()) => {
            log_stage(BootStage::IdtSetup, true);
        }
        Err(e) => {
            log_stage(BootStage::IdtSetup, false);
            match e {
                idt::IdtError::AlreadyInitialized => {
                    log("  IDT already initialized\n");
                }
                _ => boot_panic(BootError::IdtInitFailed),
            }
        }
    }

    set_stage(BootStage::MemoryValidation, rdtsc());
    match validate_memory() {
        Ok(()) => {
            log_stage(BootStage::MemoryValidation, true);

            use super::super::cpu_ops::read_cr3;
            log("  CR3: 0x");
            log_hex(read_cr3());
            log("\n");
            log("  Paging: enabled\n");
            log("  PAE: enabled\n");
            log("  Long mode: active\n");
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

    let boot_tsc = super::super::state::get_boot_tsc();
    let complete_tsc = rdtsc();
    let duration = complete_tsc - boot_tsc;
    log("Boot duration: ");
    log_hex(duration);
    log(" TSC ticks\n\n");

    if vga::is_initialized() {
        vga::set_color(vga::Color::LightGreen, vga::Color::Black);
        vga::write_str("\nBoot complete!\n");
        vga::set_color(vga::Color::LightGray, vga::Color::Black);
    }

    crate::kernel_main();
}
