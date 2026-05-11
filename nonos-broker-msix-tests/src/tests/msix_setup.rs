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

//! MSI-X test scaffolding: install a claimed PCI device with MSI-X
//! capability and a configurable test programmer, ready to drive
//! `bind_msix` end-to-end.

use crate::broker::claim;
use crate::broker::irq::msix_ops::{install_ops_for_test, MsixOps};
use crate::broker::irq::types::{IrqBindRequest, BIND_MSIX};
use crate::drivers::pci::types::{MsixInfo, PciAddress, PciBar};
use crate::fixtures::device::{good_msix_info, install_pci_msix_device, mmio_bar};
use crate::fixtures::reset::reset_all;

pub const PID: u32 = 7;
pub const DEVICE_ID: u64 = 100;

pub fn fresh(ops: &'static dyn MsixOps) -> u64 {
    reset_all();
    install_ops_for_test(ops);
    let bars = default_bars();
    install_pci_msix_device(DEVICE_ID, address(), bars, Some(good_msix_info()));
    claim::install_for_test(PID, DEVICE_ID)
}

pub fn fresh_with(
    ops: &'static dyn MsixOps,
    bars: [PciBar; 6],
    msix: Option<MsixInfo>,
) -> u64 {
    reset_all();
    install_ops_for_test(ops);
    install_pci_msix_device(DEVICE_ID, address(), bars, msix);
    claim::install_for_test(PID, DEVICE_ID)
}

pub fn address() -> PciAddress {
    PciAddress::new(0x10, 0x00, 0x00)
}

pub fn default_bars() -> [PciBar; 6] {
    let mut b = [PciBar::NotPresent; 6];
    b[0] = mmio_bar(0xFEBF_0000, 0x4000);
    b
}

pub fn msix_request(epoch: u64, vector_count: u32) -> IrqBindRequest {
    IrqBindRequest {
        device_id: DEVICE_ID,
        claim_epoch: epoch,
        irq_source: 0,
        flags: BIND_MSIX,
        vector_count,
    }
}
