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

pub mod lookup;
pub mod irq;
pub mod pci;
pub mod i2c;

pub use lookup::{get_hpet_base, get_lapic_base, get_pcie_ecam, get_ioapic_addresses, get_ioapic_for_gsi, processor_count, enabled_processor_count, has_legacy_pics, numa_domains};
pub use irq::{irq_to_gsi, is_irq_level_triggered, is_irq_active_low};
pub use pci::{PciDevice, enumerate_pci_devices, enumerate_pci_raw};
pub use i2c::{I2cHidDevice, I2cHidDeviceType, enumerate_i2c_hid_devices, find_touchpads, find_touchscreens, classify_hid_device};
