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

use super::super::config::ConfigSpace;
use super::super::constants::*;
use super::super::error::{PciError, Result};
use super::super::types::{
    MsiInfo, MsixInfo, PciCapability, PcieDeviceType, PcieInfo, PowerManagementInfo,
};

pub fn parse_msi_capability(config: &ConfigSpace, cap: &PciCapability) -> Result<MsiInfo> {
    if cap.id != CAP_ID_MSI {
        return Err(PciError::MsiNotSupported);
    }

    let msg_ctrl = config.read16(cap.offset as u16 + 2)?;

    let enabled = (msg_ctrl & MSI_CTRL_ENABLE) != 0;
    let is_64bit = (msg_ctrl & MSI_CTRL_64BIT) != 0;
    let per_vector_mask = (msg_ctrl & MSI_CTRL_PVM) != 0;
    let multi_message_capable = ((msg_ctrl & MSI_CTRL_MMC_MASK) >> 1) as u8;
    let multi_message_enabled = ((msg_ctrl & MSI_CTRL_MME_MASK) >> 4) as u8;

    Ok(MsiInfo {
        offset: cap.offset,
        is_64bit,
        per_vector_mask,
        multi_message_capable,
        multi_message_enabled,
        enabled,
    })
}

pub fn parse_msix_capability(config: &ConfigSpace, cap: &PciCapability) -> Result<MsixInfo> {
    if cap.id != CAP_ID_MSIX {
        return Err(PciError::MsixNotSupported);
    }

    let msg_ctrl = config.read16(cap.offset as u16 + 2)?;
    let table_reg = config.read32(cap.offset as u16 + 4)?;
    let pba_reg = config.read32(cap.offset as u16 + 8)?;

    let enabled = (msg_ctrl & MSIX_CTRL_ENABLE) != 0;
    let function_mask = (msg_ctrl & MSIX_CTRL_FUNCTION_MASK) != 0;
    let table_size = msg_ctrl & MSIX_CTRL_TABLE_SIZE_MASK;

    let table_bar = (table_reg & 0x7) as u8;
    let table_offset = table_reg & !0x7;

    let pba_bar = (pba_reg & 0x7) as u8;
    let pba_offset = pba_reg & !0x7;

    Ok(MsixInfo {
        offset: cap.offset,
        table_size,
        table_bar,
        table_offset,
        pba_bar,
        pba_offset,
        enabled,
        function_mask,
    })
}

pub fn parse_power_management_capability(
    config: &ConfigSpace,
    cap: &PciCapability,
) -> Result<PowerManagementInfo> {
    if cap.id != CAP_ID_PM {
        return Err(PciError::CapabilityNotFound(CAP_ID_PM));
    }

    let pmc = config.read16(cap.offset as u16 + 2)?;
    let pmcsr = config.read16(cap.offset as u16 + 4)?;

    let version = (pmc & PM_CAP_VER_MASK) as u8;
    let pme_clock = (pmc & PM_CAP_PME_CLOCK) != 0;
    let dsi = (pmc & PM_CAP_DSI) != 0;
    let aux_current = ((pmc & PM_CAP_AUX_MASK) >> 6) as u8;
    let d1_support = (pmc & PM_CAP_D1) != 0;
    let d2_support = (pmc & PM_CAP_D2) != 0;

    let pme_support = ((pmc >> 11) & 0x1F) as u8;

    let current_state = (pmcsr & PM_CTRL_STATE_MASK) as u8;
    let no_soft_reset = (pmcsr & PM_CTRL_NO_SOFT_RESET) != 0;
    let pme_enabled = (pmcsr & PM_CTRL_PME_ENABLE) != 0;
    let pme_status = (pmcsr & PM_CTRL_PME_STATUS) != 0;

    Ok(PowerManagementInfo {
        offset: cap.offset,
        version,
        pme_clock,
        dsi,
        aux_current,
        d1_support,
        d2_support,
        pme_support,
        current_state,
        no_soft_reset,
        pme_enabled,
        pme_status,
    })
}

pub fn parse_pcie_capability(config: &ConfigSpace, cap: &PciCapability) -> Result<PcieInfo> {
    if cap.id != CAP_ID_PCIE {
        return Err(PciError::PcieNotSupported);
    }

    let pcie_caps = config.read16(cap.offset as u16 + 2)?;
    let dev_caps = config.read32(cap.offset as u16 + 4)?;
    let link_caps = config.read32(cap.offset as u16 + 12)?;
    let link_status = config.read16(cap.offset as u16 + 18)?;

    let version = ((pcie_caps >> 0) & 0x0F) as u8;
    let device_type_raw = ((pcie_caps >> 4) & 0x0F) as u8;
    let slot_implemented = ((pcie_caps >> 8) & 0x01) != 0;
    let interrupt_message_number = ((pcie_caps >> 9) & 0x1F) as u8;

    let device_type = PcieDeviceType::from(device_type_raw);

    let max_payload_supported = (dev_caps & 0x07) as u8;
    let max_payload_size = 128u16 << max_payload_supported;

    let max_read_request_supported = ((dev_caps >> 12) & 0x07) as u8;
    let max_read_request_size = 128u16 << max_read_request_supported;

    let link_speed_supported = (link_caps & 0x0F) as u8;
    let link_width_supported = ((link_caps >> 4) & 0x3F) as u8;

    let link_speed = (link_status & 0x0F) as u8;
    let link_width = ((link_status >> 4) & 0x3F) as u8;

    Ok(PcieInfo {
        offset: cap.offset,
        version,
        device_type,
        slot_implemented,
        interrupt_message_number,
        max_payload_size,
        max_read_request_size,
        link_speed,
        link_width,
        link_speed_supported,
        link_width_supported,
    })
}
