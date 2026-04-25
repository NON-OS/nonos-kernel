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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use super::super::constants::*;
use super::super::types::*;
use super::detector::CorruptionDetector;
use crate::memory::layout;

pub(super) struct MemorySafety {
    pub regions: RwLock<Vec<MemoryRegion>>,
    pub protection_level: RwLock<ProtectionLevel>,
    pub corruption_detector: CorruptionDetector,
    pub access_history: RwLock<Vec<AccessPattern>>,
    pub initialized: AtomicUsize,
}

pub const REGIONS: &[MemoryRegion] = &[
    MemoryRegion::new(
        layout::KERNEL_BASE,
        layout::KERNEL_BASE + 0x400000,
        "Kernel Text",
        ProtectionLevel::Cryptographic,
        true,
        false,
        true,
        false,
    ),
    MemoryRegion::new(
        layout::KHEAP_BASE,
        layout::KHEAP_BASE + layout::KHEAP_SIZE,
        "Kernel Heap",
        ProtectionLevel::Paranoid,
        true,
        true,
        false,
        false,
    ),
    MemoryRegion::new(
        layout::DIRECTMAP_BASE,
        layout::DIRECTMAP_BASE + layout::DIRECTMAP_SIZE,
        "Direct Map",
        ProtectionLevel::Basic,
        true,
        true,
        false,
        false,
    ),
    MemoryRegion::new(
        layout::MMIO_BASE,
        layout::MMIO_BASE + layout::MMIO_SIZE,
        "MMIO Space",
        ProtectionLevel::Paranoid,
        true,
        true,
        false,
        false,
    ),
    MemoryRegion::new(
        VGA_BUFFER_START,
        VGA_BUFFER_END,
        "VGA Buffer",
        ProtectionLevel::Basic,
        true,
        true,
        false,
        false,
    ),
];

pub(super) static MEMORY_SAFETY: MemorySafety = MemorySafety::new();

impl MemorySafety {
    pub(super) const fn new() -> Self {
        Self {
            regions: RwLock::new(Vec::new()),
            protection_level: RwLock::new(ProtectionLevel::Basic),
            corruption_detector: CorruptionDetector {
                canary_base: CANARY_BASE,
                violations: AtomicUsize::new(0),
                last_check: AtomicUsize::new(0),
            },
            access_history: RwLock::new(Vec::new()),
            initialized: AtomicUsize::new(0),
        }
    }

    pub(super) fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire) != 0
    }

    pub(super) fn initialize(&self) -> Result<(), &'static str> {
        if self.initialized.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return Ok(());
        }
        let mut regions = self.regions.write();
        for region in REGIONS {
            regions.push(region.clone());
        }
        *self.protection_level.write() = ProtectionLevel::Paranoid;
        Ok(())
    }
}
