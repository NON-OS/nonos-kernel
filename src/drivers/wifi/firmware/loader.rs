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
use super::super::pcie::PcieTransport;
use super::types::{Firmware, FirmwareSection};
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints, DmaRegion};
use alloc::vec::Vec;

pub(crate) struct FirmwareLoader {
    fw_regions: Vec<DmaRegion>,
}

impl FirmwareLoader {
    pub(crate) fn new() -> Self {
        Self { fw_regions: Vec::new() }
    }

    pub(crate) fn load(
        &mut self,
        trans: &mut PcieTransport,
        fw: &Firmware,
    ) -> Result<(), WifiError> {
        crate::log::info!("iwlwifi: Loading firmware sections...");
        for section in &fw.runtime_sections {
            self.load_section(trans, section)?;
        }
        trans.grab_nic_access()?;
        trans.regs.write32(CSR_UCODE_BASE, 0);
        trans.regs.write32(CSR_UCODE_BASE + 0x04, 0);
        trans.release_nic_access();
        self.start_firmware(trans)
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
            trans.regs.write32(HBUS_TARG_MEM_RADDR, section.offset + written as u32);
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
        if !trans.regs.poll(
            csr::GP_CNTRL,
            csr_bits::GP_CNTRL_REG_FLAG_INIT_DONE,
            csr_bits::GP_CNTRL_REG_FLAG_INIT_DONE,
            ALIVE_TIMEOUT_MS * 1000,
        ) {
            crate::log_warn!("iwlwifi: Firmware did not start");
            return Err(WifiError::FirmwareLoadFailed);
        }
        crate::log::info!("iwlwifi: Firmware started successfully");
        Ok(())
    }
}
