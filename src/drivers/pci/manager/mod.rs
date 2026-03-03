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

mod device;
mod global;
mod probe;

pub use device::PciManager;
pub use global::{
    count_devices, find_device_by_class, find_device_by_id, get_device_by_address,
    get_device_by_class, get_pci_manager, get_pci_stats, init_pci, is_initialized,
    scan_and_collect, scan_and_collect_safe, with_manager,
};
