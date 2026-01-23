// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

#[derive(Debug, Clone)]
pub struct PciStats {
    pub total_devices: usize,
    pub devices_by_class: BTreeMap<u8, usize>,
    pub msix_devices: usize,
    pub dma_engines: usize,
    pub config_reads: u64,
    pub config_writes: u64,
    pub dma_transfers: u64,
    pub dma_bytes: u64,
    pub interrupts: u64,
    pub msi_interrupts: u64,
    pub errors: u64,
}

impl PciStats {
    pub const fn new() -> Self {
        Self {
            total_devices: 0,
            devices_by_class: BTreeMap::new(),
            msix_devices: 0,
            dma_engines: 0,
            config_reads: 0,
            config_writes: 0,
            dma_transfers: 0,
            dma_bytes: 0,
            interrupts: 0,
            msi_interrupts: 0,
            errors: 0,
        }
    }
}

impl Default for PciStats {
    fn default() -> Self {
        Self::new()
    }
}

pub static PCI_STATS: RwLock<PciStats> = RwLock::new(PciStats::new());

pub static INTERRUPT_COUNTER: AtomicU64 = AtomicU64::new(0);
pub static MSI_INTERRUPT_COUNTER: AtomicU64 = AtomicU64::new(0);
pub static DMA_TRANSFER_COUNTER: AtomicU64 = AtomicU64::new(0);
pub static DMA_BYTES_COUNTER: AtomicU64 = AtomicU64::new(0);
pub static CONFIG_READ_COUNTER: AtomicU64 = AtomicU64::new(0);
pub static CONFIG_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);
pub static ERROR_COUNTER: AtomicU64 = AtomicU64::new(0);

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

#[inline]
pub fn record_interrupt() {
    INTERRUPT_COUNTER.fetch_add(1, Ordering::Relaxed);
}

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
pub fn record_pci_error() {
    ERROR_COUNTER.fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pci_stats_default() {
        let stats = PciStats::new();
        assert_eq!(stats.total_devices, 0);
        assert_eq!(stats.dma_engines, 0);
    }
}
