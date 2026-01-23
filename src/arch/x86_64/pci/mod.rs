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

pub mod config;
pub mod constants;
pub mod device;
pub mod dma;
pub mod error;
pub mod io;
pub mod scan;
pub mod stats;
pub mod types;

pub use constants::{capability, class_codes, command, config as config_offsets, status, get_class_name};
pub use constants::{MAX_BARS, MAX_DEVICES_PER_BUS, MAX_FUNCTIONS_PER_DEVICE, MAX_PCI_BUSES};
pub use error::{PciError, PciResult};
pub use types::{BarType, MsixCapability, MsixTableEntry, PciBar, PciCapability};
pub use device::PciDevice;
pub use dma::{DmaBuffer, DmaDescriptor, DmaDirection, DmaEngine};
pub use stats::{get_pci_stats, record_dma_transfer, record_interrupt, record_msi_interrupt, record_pci_error, PciStats};
pub use scan::{
    find_device, find_devices_by_class, find_devices_by_class_subclass, get_cached_devices,
    init, is_initialized, scan_pci_bus,
};
pub use config::{
    pci_config_read_byte, pci_config_read_dword, pci_config_read_word,
    pci_config_write_byte, pci_config_write_dword, pci_config_write_word,
};
