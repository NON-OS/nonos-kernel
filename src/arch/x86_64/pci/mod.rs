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
pub mod constants_capability;
pub mod constants_class;
pub mod constants_command;
pub mod constants_config;
pub mod constants_general;
pub mod constants_names;
pub mod constants_status;
pub mod device;
pub mod dma;
mod dma_engine;
mod dma_transfer;
mod dma_types;
pub mod error;
pub mod io;
pub mod scan;
mod scan_core;
mod scan_find;
pub mod scan_state;
pub mod stats;
mod stats_counters;
mod stats_types;
pub mod types;
mod types_bar;
mod types_msix;

pub use config::{pci_config_read_byte, pci_config_read_dword, pci_config_read_word};
pub use config::{pci_config_write_byte, pci_config_write_dword, pci_config_write_word};
pub use constants::MAX_PCI_BUSES;
pub use constants::{capability, class_codes, command, config as config_offsets, status};
pub use constants::{get_class_name, MAX_BARS, MAX_DEVICES_PER_BUS, MAX_FUNCTIONS_PER_DEVICE};
pub use device::{parse_io_bar, parse_mem_bar, PciDevice};
pub use dma::{DmaBuffer, DmaDescriptor, DmaDirection, DmaEngine};
pub use error::{PciError, PciResult};
pub use scan::{find_device, find_devices_by_class, find_devices_by_class_subclass};
pub use scan::{get_cached_devices, init, is_initialized, scan_pci_bus};
pub use scan_state::{DEVICE_CACHE, INITIALIZED as SCAN_INITIALIZED};
pub use stats::{get_pci_stats, record_dma_transfer, record_interrupt, record_msi_interrupt};
pub use stats::{record_pci_error, PciStats};
pub use types::{BarType, MsixCapability, MsixTableEntry, PciBar, PciCapability};
