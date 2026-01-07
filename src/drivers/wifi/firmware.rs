// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::constants::*;
use super::error::WifiError;
use super::pcie::PcieTransport;
use alloc::vec::Vec;
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints, DmaRegion};

const IWL_UCODE_TLV_INST: u32 = 1;
const IWL_UCODE_TLV_DATA: u32 = 2;
const IWL_UCODE_TLV_INIT: u32 = 3;
const IWL_UCODE_TLV_INIT_DATA: u32 = 4;
const IWL_UCODE_TLV_BOOT: u32 = 5;
const IWL_UCODE_TLV_PAGING: u32 = 33;
const IWL_UCODE_TLV_SEC_RT: u32 = 20;
const IWL_UCODE_TLV_SEC_INIT: u32 = 21;
const IWL_UCODE_TLV_FW_VERSION: u32 = 36;
const IWL_UCODE_TLV_NUM_OF_CPU: u32 = 28;
const IWL_UCODE_TLV_IML: u32 = 52;

#[repr(C, packed)]
struct UcodeHeader {
    zero: u32,
    magic: u32,
    ver: u32,
    build: u32,
    ignore: u32,
}

#[repr(C, packed)]
struct TlvHeader {
    tlv_type: u32,
    length: u32,
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

impl Firmware {
    pub fn parse(data: &[u8]) -> Result<Self, WifiError> {
        if data.len() < core::mem::size_of::<UcodeHeader>() {
            return Err(WifiError::FirmwareInvalid);
        }

        // SAFETY: bounds verified, using read_unaligned for packed struct.
        let header: UcodeHeader = unsafe {
            core::ptr::read_unaligned(data.as_ptr() as *const UcodeHeader)
        };

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
            info: FirmwareInfo {
                major,
                minor,
                api,
                build: header.build,
                human_readable: [0; 64],
            },
            init_sections: Vec::new(),
            runtime_sections: Vec::new(),
            paging_sections: Vec::new(),
            iml: None,
            cpu1_cpu2_separator: None,
        };

        let tlv_start = core::mem::size_of::<UcodeHeader>();
        let mut offset = tlv_start;

        while offset + core::mem::size_of::<TlvHeader>() <= data.len() {
            // SAFETY: bounds verified, using read_unaligned for packed struct.
            let tlv: TlvHeader = unsafe {
                core::ptr::read_unaligned(data.as_ptr().add(offset) as *const TlvHeader)
            };
            let tlv_type = tlv.tlv_type;
            let tlv_len = tlv.length as usize;

            offset += core::mem::size_of::<TlvHeader>();

            if offset + tlv_len > data.len() {
                break;
            }

            let tlv_data = &data[offset..offset + tlv_len];

            match tlv_type {
                IWL_UCODE_TLV_SEC_RT => {
                    if tlv_len >= 4 {
                        let sec_offset = u32::from_le_bytes([
                            tlv_data[0],
                            tlv_data[1],
                            tlv_data[2],
                            tlv_data[3],
                        ]);
                        fw.runtime_sections.push(FirmwareSection {
                            data: tlv_data[4..].to_vec(),
                            offset: sec_offset,
                        });
                    }
                }
                IWL_UCODE_TLV_SEC_INIT => {
                    if tlv_len >= 4 {
                        let sec_offset = u32::from_le_bytes([
                            tlv_data[0],
                            tlv_data[1],
                            tlv_data[2],
                            tlv_data[3],
                        ]);
                        fw.init_sections.push(FirmwareSection {
                            data: tlv_data[4..].to_vec(),
                            offset: sec_offset,
                        });
                    }
                }
                IWL_UCODE_TLV_PAGING => {
                    if tlv_len >= 4 {
                        let sec_offset = u32::from_le_bytes([
                            tlv_data[0],
                            tlv_data[1],
                            tlv_data[2],
                            tlv_data[3],
                        ]);
                        fw.paging_sections.push(FirmwareSection {
                            data: tlv_data[4..].to_vec(),
                            offset: sec_offset,
                        });
                    }
                }
                IWL_UCODE_TLV_IML => {
                    fw.iml = Some(tlv_data.to_vec());
                }
                IWL_UCODE_TLV_FW_VERSION => {
                    let copy_len = tlv_len.min(64);
                    fw.info.human_readable[..copy_len].copy_from_slice(&tlv_data[..copy_len]);
                }
                IWL_UCODE_TLV_NUM_OF_CPU => {
                    if tlv_len >= 4 {
                        let num_cpus = u32::from_le_bytes([
                            tlv_data[0],
                            tlv_data[1],
                            tlv_data[2],
                            tlv_data[3],
                        ]);
                        if num_cpus == 2 {
                            fw.cpu1_cpu2_separator = Some(fw.runtime_sections.len() as u32);
                        }
                    }
                }
                _ => {}
            }

            offset += (tlv_len + 3) & !3;
        }

        if fw.runtime_sections.is_empty() {
            return Err(WifiError::FirmwareInvalid);
        }

        let build = { header.build };
        crate::log::info!(
            "iwlwifi: Parsed firmware v{}.{}.{} build {}",
            major,
            minor,
            api,
            build
        );

        Ok(fw)
    }
}

pub struct FirmwareLoader {
    fw_regions: Vec<DmaRegion>,
}

impl FirmwareLoader {
    pub fn new() -> Self {
        Self {
            fw_regions: Vec::new(),
        }
    }

    pub fn load(&mut self, trans: &mut PcieTransport, fw: &Firmware) -> Result<(), WifiError> {
        crate::log::info!("iwlwifi: Loading firmware sections...");

        for section in &fw.runtime_sections {
            self.load_section(trans, section)?;
        }

        trans.grab_nic_access()?;

        trans.regs.write32(CSR_UCODE_BASE, 0);
        trans.regs.write32(CSR_UCODE_BASE + 0x04, 0);

        trans.release_nic_access();

        self.start_firmware(trans)?;

        Ok(())
    }

    fn load_section(
        &mut self,
        trans: &mut PcieTransport,
        section: &FirmwareSection,
    ) -> Result<(), WifiError> {
        let constraints = DmaConstraints {
            alignment: 16,
            max_segment_size: section.data.len(),
            dma32_only: false,
            coherent: true,
        };

        let region =
            alloc_dma_coherent(section.data.len(), constraints).map_err(|_| WifiError::DmaError)?;

        // SAFETY: region is valid DMA memory with sufficient size.
        unsafe {
            core::ptr::copy_nonoverlapping(
                section.data.as_ptr(),
                region.virt_addr.as_mut_ptr(),
                section.data.len(),
            );
        }

        trans.grab_nic_access()?;

        let mut written = 0;

        while written < section.data.len() {
            let chunk_size = (section.data.len() - written).min(DMA_BLOCK_SIZE);
            let dest_addr = section.offset + written as u32;

            trans.regs.write32(HBUS_TARG_MEM_RADDR, dest_addr);

            for i in (0..chunk_size).step_by(4) {
                let word = if i + 4 <= chunk_size {
                    u32::from_le_bytes([
                        section.data[written + i],
                        section.data[written + i + 1],
                        section.data[written + i + 2],
                        section.data[written + i + 3],
                    ])
                } else {
                    let mut bytes = [0u8; 4];
                    for j in 0..(chunk_size - i) {
                        bytes[j] = section.data[written + i + j];
                    }
                    u32::from_le_bytes(bytes)
                };
                trans.regs.write32(HBUS_TARG_MEM_WDAT, word);
            }

            written += chunk_size;
        }

        trans.release_nic_access();
        self.fw_regions.push(region);

        Ok(())
    }

    fn start_firmware(&mut self, trans: &mut PcieTransport) -> Result<(), WifiError> {
        trans.regs.write32(csr::RESET, 0);

        let timeout_us = ALIVE_TIMEOUT_MS * 1000;
        if !trans.regs.poll(
            csr::GP_CNTRL,
            csr_bits::GP_CNTRL_REG_FLAG_INIT_DONE,
            csr_bits::GP_CNTRL_REG_FLAG_INIT_DONE,
            timeout_us,
        ) {
            crate::log_warn!("iwlwifi: Firmware did not start");
            return Err(WifiError::FirmwareLoadFailed);
        }

        crate::log::info!("iwlwifi: Firmware started successfully");
        Ok(())
    }
}
