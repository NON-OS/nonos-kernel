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

#[derive(Debug, Clone, Copy)]
pub struct PciWriteRequest {
    pub device_id: u64,
    pub claim_epoch: u64,
    pub offset: u32,
    pub value: u16,
}

// `Command` carries the new u16 the capsule wants written into
// CFG_COMMAND; only bit 2 (Bus Master Enable) may differ from the
// current register. `MsixControl` carries the new u16 for the
// MSI-X capability's Message Control register; only Function Mask
// and Enable bits may differ. The handler dispatches on the variant
// to the matching `ConfigSpace::write16` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteAction {
    Command(u16),
    MsixControl { offset: u16, value: u16 },
}

// A device with no MSI-X capability that names an offset other
// than `CFG_COMMAND` falls through to `OffsetNotAllowed` — the
// validator does not synthesise a "would-be" MSI-X control offset
// to reject against, because nothing in the kernel can read or
// write a non-existent capability register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciWriteError {
    NotClaimed,
    StaleEpoch,
    NoDeviceHandle,
    OffsetNotAllowed,
    BitsNotAllowed,
    PlatformError,
}
