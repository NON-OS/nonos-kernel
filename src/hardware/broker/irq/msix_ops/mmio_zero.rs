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

// x86-only: MSI-X entry layout (msg-addr-lo/hi, data, vector-control).
#![cfg(target_arch = "x86_64")]

use crate::drivers::pci::types::{MsixInfo, PciBar};

pub(super) fn zero_table_entry(msix: &MsixInfo, bars: &[PciBar; 6], device_vector: u16) {
    let _ = crate::drivers::pci::msi::zero_msix_vector(msix, bars, device_vector);
}
