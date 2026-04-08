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

pub use super::stats_types::PciStats;
pub use super::stats_counters::{
    get_pci_stats, record_dma_transfer, record_interrupt, record_msi_interrupt, record_pci_error,
    CONFIG_READ_COUNTER, CONFIG_WRITE_COUNTER, DMA_BYTES_COUNTER, DMA_TRANSFER_COUNTER,
    ERROR_COUNTER, INTERRUPT_COUNTER, MSI_INTERRUPT_COUNTER, PCI_STATS,
};
