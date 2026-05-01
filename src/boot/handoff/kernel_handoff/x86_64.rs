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

// x86_64 constructor for `KernelHandoff`. Reads the UEFI-derived
// `BootHandoffV1` and projects it into the cross-arch shape. The
// produced handoff borrows from the input `BootHandoffV1` for its
// arch-specific tail, so the lifetime of the returned `KernelHandoff`
// is bounded by the original handoff.

use super::super::types::handoff::BootHandoffV1;
use super::arch::ArchSpecificHandoff;
use super::console::EarlyConsole;
use super::cpu::CpuTopology;
use super::framebuffer::Framebuffer;
use super::measurement::Measurement;
use super::memory::MemoryHandoff;
use super::timing::TimingHandoff;
use super::KernelHandoff;

// Legacy x86 serial port base used as the early-debug console on every
// production NONOS x86_64 boot.
const X86_LEGACY_SERIAL_PORT: u16 = 0x3F8;

impl<'a> KernelHandoff<'a> {
    pub fn from_x86_64(handoff: &'a BootHandoffV1) -> Self {
        Self {
            memory: build_memory(handoff),
            cpus: build_cpus(handoff),
            console: EarlyConsole::LegacySerial(X86_LEGACY_SERIAL_PORT),
            framebuffer: build_framebuffer(handoff),
            timing: build_timing(handoff),
            measurement: build_measurement(handoff),
            arch: ArchSpecificHandoff::X86_64 { v1: handoff },
        }
    }
}

fn build_memory(handoff: &BootHandoffV1) -> MemoryHandoff {
    // SAFETY: `usable_regions` walks the EFI memory descriptor array
    // pointed to by `handoff.mmap.ptr`. The pointer is valid for the
    // lifetime of the handoff structure. We only read it to find the
    // largest contiguous usable region, no writes occur.
    let largest_usable_bytes = unsafe {
        handoff
            .mmap
            .usable_regions()
            .map(|(start, end)| end.saturating_sub(start))
            .max()
            .unwrap_or(0)
    };
    MemoryHandoff {
        map_ptr: handoff.mmap.ptr,
        map_entries: handoff.mmap.entry_count,
        largest_usable_bytes,
    }
}

fn build_cpus(_handoff: &BootHandoffV1) -> CpuTopology {
    // The x86_64 BootHandoffV1 does not carry CPU topology. The boot
    // CPU (BSP) is implicitly id 0; secondary CPUs come up later via
    // `smp::start_aps`. When the handoff is extended to carry the ACPI
    // MADT-parsed CPU set, this function reads the count from there.
    CpuTopology { boot_cpu_id: 0, cpu_count: 1 }
}

fn build_framebuffer(handoff: &BootHandoffV1) -> Option<Framebuffer> {
    handoff.framebuffer().map(|fb| Framebuffer {
        base: fb.ptr,
        size: fb.size,
        width: fb.width,
        height: fb.height,
        stride: fb.stride,
        cursor_y: fb.cursor_y,
    })
}

fn build_timing(handoff: &BootHandoffV1) -> TimingHandoff {
    let fixed_freq_hz = if handoff.timing.tsc_hz != 0 {
        Some(handoff.timing.tsc_hz)
    } else {
        None
    };
    TimingHandoff { fixed_freq_hz, unix_epoch_ms: handoff.timing.unix_epoch_ms }
}

fn build_measurement(handoff: &BootHandoffV1) -> Measurement {
    Measurement {
        secure_boot: handoff.secure_boot_enabled(),
        kernel_signature_verified: handoff.kernel_verified(),
    }
}
