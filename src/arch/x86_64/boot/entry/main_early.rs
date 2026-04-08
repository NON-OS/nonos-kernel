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
use super::super::state::{set_boot_tsc, set_stage};
use super::super::validation::validate_cpu_features;
use super::log::{log, log_stage};
use super::main_cpu::init_cpu_success;
use super::main_late::boot_late;
use super::panic::boot_panic;
use crate::arch::x86_64::{cpu, gdt, serial, vga};

#[no_mangle]
pub unsafe extern "C" fn boot_main() -> ! {
    set_boot_tsc(rdtsc());
    set_stage(BootStage::Entry, rdtsc());
    set_stage(BootStage::SerialInit, rdtsc());
    if serial::init().is_ok() {
        log("\n================================================================================\n");
        log("                           NONOS x86_64 Boot                                   \n");
        log("================================================================================\n\n");
        log_stage(BootStage::SerialInit, true);
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
        Err(_) => log_stage(BootStage::VgaInit, false),
    }
    set_stage(BootStage::CpuDetect, rdtsc());
    match cpu::init() {
        Ok(()) => init_cpu_success(),
        Err(e) => {
            log_stage(BootStage::CpuDetect, false);
            match e {
                cpu::CpuError::NoCpuid => boot_panic(BootError::NoCpuid),
                cpu::CpuError::NoLongMode => boot_panic(BootError::NoLongMode),
                _ => boot_panic(BootError::CpuInitFailed),
            }
        }
    }
    if let Err(e) = validate_cpu_features() { boot_panic(e); }
    set_stage(BootStage::GdtSetup, rdtsc());
    match gdt::init() {
        Ok(()) => log_stage(BootStage::GdtSetup, true),
        Err(gdt::GdtError::AlreadyInitialized) => log("  GDT already initialized\n"),
        Err(_) => { log_stage(BootStage::GdtSetup, false); boot_panic(BootError::GdtInitFailed); }
    }
    boot_late()
}
