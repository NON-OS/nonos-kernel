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

use super::super::constants::*;
use super::super::types::{Region, RegionKind};
use super::align::{align_down, align_up};
use super::kaslr_ops::slid_address;
use super::state::{kernel_sections, LAYOUT};

pub fn region_from_firmware(kind_code: u32, start: u64, len: u64) -> Region {
    let kind = match kind_code {
        FIRMWARE_REGION_USABLE => RegionKind::Usable,
        FIRMWARE_REGION_RESERVED => RegionKind::Reserved,
        FIRMWARE_REGION_ACPI_RECLAIM | FIRMWARE_REGION_ACPI_NVS => RegionKind::Acpi,
        FIRMWARE_REGION_MMIO => RegionKind::Mmio,
        _ => RegionKind::Unknown,
    };
    Region::new(start, start.saturating_add(len), kind)
}

pub fn managed_span(regions: &[Region]) -> (u64, u64) {
    let (mut lo, mut hi) = (u64::MAX, 0u64);
    for region in regions {
        if region.is_usable() {
            let (start, end) =
                (align_up(region.start, PAGE_SIZE_U64), align_down(region.end, PAGE_SIZE_U64));
            if end > start {
                lo = lo.min(start);
                hi = hi.max(end);
            }
        }
    }
    if lo > hi {
        (0, 0)
    } else {
        (lo, hi)
    }
}

pub fn log_kernel_sections(mut log: impl FnMut(&str)) {
    for section in kernel_sections().iter() {
        let perm = if section.rx {
            "RX"
        } else if section.rw {
            "RW"
        } else {
            "R-"
        };
        let nx = if section.nx { "NX" } else { "X-" };
        log(&alloc::format!(
            "[layout] {:#016x}-{:#016x} {:>6}KiB {} {} global={}",
            slid_address(section.start),
            slid_address(section.end),
            section.size() / 1024,
            perm,
            nx,
            section.global
        ));
    }
}

pub fn layout_summary() -> alloc::string::String {
    let layout = LAYOUT.read();
    alloc::format!("Layout {{ slide: {:#x}, heap: {:#x}+{:#x}, vm: {:#x}+{:#x}, mmio: {:#x}+{:#x}, init: {} }}", layout.slide, layout.heap_lo, layout.heap_sz, layout.vm_lo, layout.vm_sz, layout.mmio_lo, layout.mmio_sz, layout.initialized)
}
