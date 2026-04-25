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

mod atomics;
mod device_class;
mod getters;
mod pci_stats;
mod performance;
mod record;

pub use device_class::DeviceClassStats;
pub use getters::{
    get_msi_capable_devices, get_msix_capable_devices, get_pcie_devices, get_total_devices,
};
pub use pci_stats::PciStats;
pub use performance::PerformanceMetrics;
pub use record::{
    record_config_error, record_config_read, record_config_write, record_device_found,
    record_enumeration, record_error_event, record_hotplug_event, record_interrupt,
    record_link_state_change, record_power_state_change, reset_stats,
};
