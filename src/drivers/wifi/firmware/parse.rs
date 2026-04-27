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

use super::super::constants::*;
use super::super::error::WifiError;
use super::types::*;
use alloc::vec::Vec;

impl Firmware {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, WifiError> {
        if data.len() < core::mem::size_of::<UcodeHeader>() {
            return Err(WifiError::FirmwareInvalid);
        }
        let header: UcodeHeader =
            unsafe { core::ptr::read_unaligned(data.as_ptr() as *const UcodeHeader) };
        if header.zero != 0 || header.magic != IWL_FW_MAGIC {
            return Err(WifiError::FirmwareInvalid);
        }
        let ver = header.ver;
        let major = ((ver >> 24) & 0xFF) as u16;
        let minor = ((ver >> 16) & 0xFF) as u16;
        let api = (ver & FW_API_VERSION_MASK) as u16;
        if api < MIN_FW_API_VERSION || api > MAX_FW_API_VERSION {
            crate::log_warn!("iwlwifi: Firmware API {} not supported", api);
            return Err(WifiError::FirmwareInvalid);
        }
        let mut fw = Firmware {
            info: FirmwareInfo { major, minor, api, build: header.build, human_readable: [0; 64] },
            init_sections: Vec::new(),
            runtime_sections: Vec::new(),
            paging_sections: Vec::new(),
            iml: None,
            cpu1_cpu2_separator: None,
        };
        let mut offset = core::mem::size_of::<UcodeHeader>();
        while offset + core::mem::size_of::<TlvHeader>() <= data.len() {
            let tlv: TlvHeader =
                unsafe { core::ptr::read_unaligned(data.as_ptr().add(offset) as *const TlvHeader) };
            let tlv_len = tlv.length as usize;
            offset += core::mem::size_of::<TlvHeader>();
            if offset + tlv_len > data.len() {
                break;
            }
            let tlv_data = &data[offset..offset + tlv_len];
            match tlv.tlv_type {
                IWL_UCODE_TLV_SEC_RT => {
                    if tlv_len >= 4 {
                        fw.runtime_sections.push(FirmwareSection {
                            data: tlv_data[4..].to_vec(),
                            offset: u32::from_le_bytes([
                                tlv_data[0],
                                tlv_data[1],
                                tlv_data[2],
                                tlv_data[3],
                            ]),
                        });
                    }
                }
                IWL_UCODE_TLV_SEC_INIT => {
                    if tlv_len >= 4 {
                        fw.init_sections.push(FirmwareSection {
                            data: tlv_data[4..].to_vec(),
                            offset: u32::from_le_bytes([
                                tlv_data[0],
                                tlv_data[1],
                                tlv_data[2],
                                tlv_data[3],
                            ]),
                        });
                    }
                }
                IWL_UCODE_TLV_PAGING => {
                    if tlv_len >= 4 {
                        fw.paging_sections.push(FirmwareSection {
                            data: tlv_data[4..].to_vec(),
                            offset: u32::from_le_bytes([
                                tlv_data[0],
                                tlv_data[1],
                                tlv_data[2],
                                tlv_data[3],
                            ]),
                        });
                    }
                }
                IWL_UCODE_TLV_IML => {
                    fw.iml = Some(tlv_data.to_vec());
                }
                IWL_UCODE_TLV_FW_VERSION => {
                    fw.info.human_readable[..tlv_len.min(64)]
                        .copy_from_slice(&tlv_data[..tlv_len.min(64)]);
                }
                IWL_UCODE_TLV_NUM_OF_CPU => {
                    if tlv_len >= 4
                        && u32::from_le_bytes([tlv_data[0], tlv_data[1], tlv_data[2], tlv_data[3]])
                            == 2
                    {
                        fw.cpu1_cpu2_separator = Some(fw.runtime_sections.len() as u32);
                    }
                }
                _ => {}
            }
            offset += (tlv_len + 3) & !3;
        }
        if fw.runtime_sections.is_empty() {
            return Err(WifiError::FirmwareInvalid);
        }
        let build = header.build;
        crate::log::info!("iwlwifi: Parsed firmware v{}.{}.{} build {}", major, minor, api, build);
        Ok(fw)
    }
}
