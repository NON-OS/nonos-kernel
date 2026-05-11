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

//! Shared scaffolding for `MkPciConfigWrite` tests. The MSI-X
//! capability sits at offset `0x40` so the Message Control register
//! the validator allows writes to is `0x42`.

use crate::broker::pci::types::PciWriteRequest;
use crate::drivers::pci::types::MsixInfo;

pub const MSIX_CAP_OFFSET: u8 = 0x40;
pub const MSIX_CTRL_OFFSET: u32 = (MSIX_CAP_OFFSET as u32) + 2;

pub fn msix_info() -> MsixInfo {
    MsixInfo {
        offset: MSIX_CAP_OFFSET,
        table_size: 7,
        table_bar: 0,
        table_offset: 0x1000,
        pba_bar: 0,
        pba_offset: 0x2000,
        enabled: false,
        function_mask: false,
    }
}

pub fn req(offset: u32, value: u16) -> PciWriteRequest {
    PciWriteRequest { device_id: 0, claim_epoch: 0, offset, value }
}
