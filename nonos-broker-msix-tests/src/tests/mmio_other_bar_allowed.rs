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

//! Mapping a BAR that does not host the MSI-X table or PBA must
//! be unaffected by the exclusion check — devices put NVMe queues,
//! AHCI HBA registers, and similar driver-facing regions in their
//! own BARs and the kernel must keep those reachable.

use crate::broker::mmio::msix_exclusion::validate;

use super::pci_setup::msix_info;

#[test]
fn unrelated_bar_passes() {
    let m = msix_info();
    let other_bar = if m.table_bar == 0 && m.pba_bar == 0 { 1 } else { 0 };
    validate(Some(&m), other_bar, 0x0000, 0x1000).expect("unrelated BAR is fine");
}

#[test]
fn no_msix_cap_passes() {
    validate(None, 0, 0x0000, 0x1000).expect("no msix means no exclusion");
}
