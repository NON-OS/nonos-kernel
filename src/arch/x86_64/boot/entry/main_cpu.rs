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

use super::super::stage::BootStage;
use super::log::{log, log_stage};
use crate::arch::x86_64::{cpu, vga};

pub fn init_cpu_success() {
    log_stage(BootStage::CpuDetect, true);
    let features = cpu::features();
    let vendor = cpu::vendor();
    log("  Vendor: ");
    match vendor {
        cpu::CpuVendor::Intel => log("Intel"),
        cpu::CpuVendor::Amd => log("AMD"),
        _ => log("Other"),
    }
    log("\n  Features:");
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
