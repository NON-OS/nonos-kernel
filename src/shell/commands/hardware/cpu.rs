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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN};
use crate::shell::commands::utils::format_num_simple;

pub fn cmd_lscpu() {
    print_line(b"CPU Information:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);

    let (vendor, family, model, stepping) = get_cpuid_info();

    let mut line = [0u8; 64];
    line[..12].copy_from_slice(b"Vendor:     ");
    let vendor_len = vendor.len().min(48);
    line[12..12+vendor_len].copy_from_slice(&vendor[..vendor_len]);
    print_line(&line[..12+vendor_len], COLOR_TEXT);

    line[..12].copy_from_slice(b"Family:     ");
    let len = format_num_simple(&mut line[12..], family as usize);
    print_line(&line[..12+len], COLOR_TEXT);

    line[..12].copy_from_slice(b"Model:      ");
    let len = format_num_simple(&mut line[12..], model as usize);
    print_line(&line[..12+len], COLOR_TEXT);

    line[..12].copy_from_slice(b"Stepping:   ");
    let len = format_num_simple(&mut line[12..], stepping as usize);
    print_line(&line[..12+len], COLOR_TEXT);

    print_line(b"", COLOR_TEXT);
    print_line(b"Architecture:   x86_64 (AMD64)", COLOR_TEXT);
    print_line(b"Mode:           Long Mode (64-bit)", COLOR_TEXT);
    print_line(b"Byte Order:     Little Endian", COLOR_TEXT);

    print_line(b"", COLOR_TEXT);
    print_line(b"Features:", COLOR_TEXT_WHITE);

    let features = get_cpu_features();
    if features & (1 << 0) != 0 { print_line(b"  SSE", COLOR_GREEN); }
    if features & (1 << 1) != 0 { print_line(b"  SSE2", COLOR_GREEN); }
    if features & (1 << 2) != 0 { print_line(b"  SSE3", COLOR_GREEN); }
    if features & (1 << 3) != 0 { print_line(b"  SSE4.1", COLOR_GREEN); }
    if features & (1 << 4) != 0 { print_line(b"  SSE4.2", COLOR_GREEN); }
    if features & (1 << 5) != 0 { print_line(b"  AVX", COLOR_GREEN); }
    if features & (1 << 6) != 0 { print_line(b"  AVX2", COLOR_GREEN); }
    if features & (1 << 7) != 0 { print_line(b"  AES-NI", COLOR_GREEN); }
    if features & (1 << 8) != 0 { print_line(b"  RDRAND", COLOR_GREEN); }
}

fn get_cpuid_info() -> (&'static [u8], u32, u32, u32) {
    let ebx: u32;
    let ecx: u32;
    let edx: u32;

    // SAFETY: CPUID is a safe instruction that returns CPU identification info.
    // We preserve rbx since LLVM uses it internally.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") 0u32 => _,
            ebx_out = out(reg) ebx,
            out("ecx") ecx,
            out("edx") edx,
            options(nomem)
        );
    }

    let vendor: &[u8] = if ebx == 0x756E6547 && edx == 0x49656E69 && ecx == 0x6C65746E {
        b"GenuineIntel"
    } else if ebx == 0x68747541 && edx == 0x69746E65 && ecx == 0x444D4163 {
        b"AuthenticAMD"
    } else {
        b"Unknown"
    };

    let eax1: u32;
    // SAFETY: CPUID with EAX=1 returns processor info and feature flags.
    // We preserve rbx since LLVM uses it internally.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 1u32 => eax1,
            out("ecx") _,
            out("edx") _,
            options(nomem)
        );
    }

    let stepping = eax1 & 0xF;
    let model = ((eax1 >> 4) & 0xF) | ((eax1 >> 12) & 0xF0);
    let family = ((eax1 >> 8) & 0xF) + ((eax1 >> 20) & 0xFF);

    (vendor, family, model, stepping)
}

fn get_cpu_features() -> u32 {
    let ecx: u32;
    let edx: u32;

    // SAFETY: CPUID with EAX=1 returns feature flags in ECX and EDX.
    // We preserve rbx since LLVM uses it internally.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 1u32 => _,
            out("ecx") ecx,
            out("edx") edx,
            options(nomem)
        );
    }

    let mut features = 0u32;

    if edx & (1 << 25) != 0 { features |= 1 << 0; }
    if edx & (1 << 26) != 0 { features |= 1 << 1; }
    if ecx & (1 << 0) != 0 { features |= 1 << 2; }
    if ecx & (1 << 19) != 0 { features |= 1 << 3; }
    if ecx & (1 << 20) != 0 { features |= 1 << 4; }
    if ecx & (1 << 28) != 0 { features |= 1 << 5; }
    if ecx & (1 << 25) != 0 { features |= 1 << 7; }
    if ecx & (1 << 30) != 0 { features |= 1 << 8; }

    let ebx7: u32;
    // SAFETY: CPUID with EAX=7, ECX=0 returns extended feature flags.
    // We preserve rbx since LLVM uses it internally.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") 7u32 => _,
            inout("ecx") 0u32 => _,
            ebx_out = out(reg) ebx7,
            out("edx") _,
            options(nomem)
        );
    }

    if ebx7 & (1 << 5) != 0 { features |= 1 << 6; }

    features
}
