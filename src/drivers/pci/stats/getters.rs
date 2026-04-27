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

use super::atomics::*;
use core::sync::atomic::Ordering;

pub fn get_total_devices() -> u64 {
    TOTAL_DEVICES.load(Ordering::Relaxed)
}
pub fn get_pcie_devices() -> u64 {
    PCIE_DEVICES.load(Ordering::Relaxed)
}
pub fn get_msi_capable_devices() -> u64 {
    MSI_CAPABLE_DEVICES.load(Ordering::Relaxed)
}
pub fn get_msix_capable_devices() -> u64 {
    MSIX_CAPABLE_DEVICES.load(Ordering::Relaxed)
}
