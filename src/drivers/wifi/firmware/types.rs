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

use alloc::vec::Vec;

pub(super) const IWL_UCODE_TLV_PAGING: u32 = 33;
pub(super) const IWL_UCODE_TLV_SEC_RT: u32 = 20;
pub(super) const IWL_UCODE_TLV_SEC_INIT: u32 = 21;
pub(super) const IWL_UCODE_TLV_FW_VERSION: u32 = 36;
pub(super) const IWL_UCODE_TLV_NUM_OF_CPU: u32 = 28;
pub(super) const IWL_UCODE_TLV_IML: u32 = 52;

#[repr(C, packed)]
pub(super) struct UcodeHeader {
    pub zero: u32,
    pub magic: u32,
    pub ver: u32,
    pub build: u32,
    pub ignore: u32,
}
#[repr(C, packed)]
pub(super) struct TlvHeader {
    pub tlv_type: u32,
    pub length: u32,
}

#[derive(Debug, Clone)]
pub struct FirmwareInfo {
    pub major: u16,
    pub minor: u16,
    pub api: u16,
    pub build: u32,
    pub human_readable: [u8; 64],
}

pub struct FirmwareSection {
    pub data: Vec<u8>,
    pub offset: u32,
}

pub struct Firmware {
    pub info: FirmwareInfo,
    pub init_sections: Vec<FirmwareSection>,
    pub runtime_sections: Vec<FirmwareSection>,
    pub paging_sections: Vec<FirmwareSection>,
    pub iml: Option<Vec<u8>>,
    pub cpu1_cpu2_separator: Option<u32>,
}
