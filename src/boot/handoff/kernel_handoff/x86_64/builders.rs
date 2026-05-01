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

use super::super::cpu::CpuTopology;
use super::super::framebuffer::Framebuffer;
use super::super::measurement::Measurement;
use super::super::memory::MemoryHandoff;
use super::super::timing::TimingHandoff;
use crate::boot::handoff::BootHandoffV1;

pub(super) fn memory(handoff: &BootHandoffV1) -> MemoryHandoff {
    // SAFETY: `usable_regions` walks the EFI descriptor array at
    // `handoff.mmap.ptr`. Pointer is valid for the lifetime of the
    // handoff; we only read.
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

pub(super) fn cpus(_handoff: &BootHandoffV1) -> CpuTopology {
    CpuTopology { boot_cpu_id: 0, cpu_count: 1 }
}

pub(super) fn framebuffer(handoff: &BootHandoffV1) -> Option<Framebuffer> {
    handoff.framebuffer().map(|fb| Framebuffer {
        base: fb.ptr,
        size: fb.size,
        width: fb.width,
        height: fb.height,
        stride: fb.stride,
        cursor_y: fb.cursor_y,
    })
}

pub(super) fn timing(handoff: &BootHandoffV1) -> TimingHandoff {
    let fixed_freq_hz = if handoff.timing.tsc_hz != 0 {
        Some(handoff.timing.tsc_hz)
    } else {
        None
    };
    TimingHandoff { fixed_freq_hz, unix_epoch_ms: handoff.timing.unix_epoch_ms }
}

pub(super) fn measurement(handoff: &BootHandoffV1) -> Measurement {
    Measurement {
        secure_boot: handoff.secure_boot_enabled(),
        kernel_signature_verified: handoff.kernel_verified(),
    }
}
