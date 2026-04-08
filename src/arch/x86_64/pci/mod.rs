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

pub mod config;
mod config_core;
mod config_helpers;
pub mod constants;
mod constants_general;
mod constants_config;
mod constants_command;
mod constants_status;
mod constants_capability;
mod constants_class;
mod constants_names;
pub mod device;
pub mod dma;
mod dma_types;
mod dma_engine;
mod dma_transfer;
pub mod error;
pub mod io;
pub mod scan;
mod scan_state;
mod scan_core;
mod scan_find;
pub mod stats;
mod stats_types;
mod stats_counters;
pub mod types;
mod types_bar;
mod types_msix;

pub use constants::{capability, class_codes, command, config as config_offsets, status};
pub use constants::{get_class_name, MAX_BARS, MAX_DEVICES_PER_BUS, MAX_FUNCTIONS_PER_DEVICE};
pub use constants::MAX_PCI_BUSES;
pub use error::{PciError, PciResult};
pub use types::{BarType, MsixCapability, MsixTableEntry, PciBar, PciCapability};
pub use device::PciDevice;
pub use dma::{DmaBuffer, DmaDescriptor, DmaDirection, DmaEngine};
pub use stats::{get_pci_stats, record_dma_transfer, record_interrupt, record_msi_interrupt};
pub use stats::{record_pci_error, PciStats};
pub use scan::{find_device, find_devices_by_class, find_devices_by_class_subclass};
pub use scan::{get_cached_devices, init, is_initialized, scan_pci_bus};
pub use config::{pci_config_read_byte, pci_config_read_dword, pci_config_read_word};
pub use config::{pci_config_write_byte, pci_config_write_dword, pci_config_write_word};
