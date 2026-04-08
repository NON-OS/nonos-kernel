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

use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;
use super::stats_types::PciStats;

pub static PCI_STATS: RwLock<PciStats> = RwLock::new(PciStats::new());
pub static INTERRUPT_COUNTER: AtomicU64 = AtomicU64::new(0);
pub static MSI_INTERRUPT_COUNTER: AtomicU64 = AtomicU64::new(0);
pub static DMA_TRANSFER_COUNTER: AtomicU64 = AtomicU64::new(0);
pub static DMA_BYTES_COUNTER: AtomicU64 = AtomicU64::new(0);
pub static CONFIG_READ_COUNTER: AtomicU64 = AtomicU64::new(0);
pub static CONFIG_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);
pub static ERROR_COUNTER: AtomicU64 = AtomicU64::new(0);

#[inline]
pub fn record_interrupt() { INTERRUPT_COUNTER.fetch_add(1, Ordering::Relaxed); }

#[inline]
pub fn record_msi_interrupt() {
    MSI_INTERRUPT_COUNTER.fetch_add(1, Ordering::Relaxed);
    INTERRUPT_COUNTER.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn record_dma_transfer(bytes: u64) {
    DMA_TRANSFER_COUNTER.fetch_add(1, Ordering::Relaxed);
    DMA_BYTES_COUNTER.fetch_add(bytes, Ordering::Relaxed);
}

#[inline]
pub fn record_pci_error() { ERROR_COUNTER.fetch_add(1, Ordering::Relaxed); }

pub fn get_pci_stats() -> PciStats {
    let stats = PCI_STATS.read();
    PciStats {
        total_devices: stats.total_devices,
        devices_by_class: stats.devices_by_class.clone(),
        msix_devices: stats.msix_devices,
        dma_engines: stats.dma_engines,
        config_reads: CONFIG_READ_COUNTER.load(Ordering::Relaxed),
        config_writes: CONFIG_WRITE_COUNTER.load(Ordering::Relaxed),
        dma_transfers: DMA_TRANSFER_COUNTER.load(Ordering::Relaxed),
        dma_bytes: DMA_BYTES_COUNTER.load(Ordering::Relaxed),
        interrupts: INTERRUPT_COUNTER.load(Ordering::Relaxed),
        msi_interrupts: MSI_INTERRUPT_COUNTER.load(Ordering::Relaxed),
        errors: ERROR_COUNTER.load(Ordering::Relaxed),
    }
}
