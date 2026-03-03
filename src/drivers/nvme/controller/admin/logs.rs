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

use super::super::super::constants::*;
use super::super::super::dma::DmaRegion;
use super::super::super::error::NvmeError;
use super::super::super::queue::AdminQueue;
use super::super::super::types::SubmissionEntry;

pub fn get_log_page(
    admin_queue: &AdminQueue,
    lid: u8,
    nsid: u32,
    buffer_size: usize,
) -> Result<DmaRegion, NvmeError> {
    let buffer = DmaRegion::allocate(buffer_size)?;

    let numdl = ((buffer_size / 4) - 1) as u16;
    let cmd = SubmissionEntry::build_get_log_page(0, nsid, lid, numdl, buffer.phys_u64());

    let _completion = admin_queue.submit_and_wait(cmd)?;
    Ok(buffer)
}

pub fn get_smart_log(admin_queue: &AdminQueue, nsid: u32) -> Result<SmartLog, NvmeError> {
    let buffer = get_log_page(admin_queue, LID_SMART_HEALTH, nsid, 512)?;

    let data = buffer.as_slice::<u8>();
    Ok(SmartLog::from_data(data))
}

#[derive(Debug, Clone)]
pub struct SmartLog {
    pub critical_warning: u8,
    pub temperature: u16,
    pub available_spare: u8,
    pub available_spare_threshold: u8,
    pub percentage_used: u8,
    pub endurance_group_critical_warning: u8,
    pub data_units_read: u128,
    pub data_units_written: u128,
    pub host_read_commands: u128,
    pub host_write_commands: u128,
    pub controller_busy_time: u128,
    pub power_cycles: u128,
    pub power_on_hours: u128,
    pub unsafe_shutdowns: u128,
    pub media_errors: u128,
    pub num_error_log_entries: u128,
    pub warning_composite_temp_time: u32,
    pub critical_composite_temp_time: u32,
}

impl SmartLog {
    pub fn from_data(data: &[u8]) -> Self {
        let read_u128 = |offset: usize| -> u128 {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&data[offset..offset + 16]);
            u128::from_le_bytes(bytes)
        };

        Self {
            critical_warning: data[0],
            temperature: u16::from_le_bytes([data[1], data[2]]),
            available_spare: data[3],
            available_spare_threshold: data[4],
            percentage_used: data[5],
            endurance_group_critical_warning: data[6],
            data_units_read: read_u128(32),
            data_units_written: read_u128(48),
            host_read_commands: read_u128(64),
            host_write_commands: read_u128(80),
            controller_busy_time: read_u128(96),
            power_cycles: read_u128(112),
            power_on_hours: read_u128(128),
            unsafe_shutdowns: read_u128(144),
            media_errors: read_u128(160),
            num_error_log_entries: read_u128(176),
            warning_composite_temp_time: u32::from_le_bytes([
                data[192], data[193], data[194], data[195],
            ]),
            critical_composite_temp_time: u32::from_le_bytes([
                data[196], data[197], data[198], data[199],
            ]),
        }
    }

    pub fn temperature_celsius(&self) -> i16 {
        (self.temperature as i16) - 273
    }

    pub fn has_critical_warning(&self) -> bool {
        self.critical_warning != 0
    }

    pub fn is_spare_low(&self) -> bool {
        (self.critical_warning & 0x01) != 0
    }

    pub fn is_temperature_critical(&self) -> bool {
        (self.critical_warning & 0x02) != 0
    }

    pub fn is_reliability_degraded(&self) -> bool {
        (self.critical_warning & 0x04) != 0
    }

    pub fn is_read_only(&self) -> bool {
        (self.critical_warning & 0x08) != 0
    }

    pub fn has_volatile_backup_failed(&self) -> bool {
        (self.critical_warning & 0x10) != 0
    }
}

pub fn format_nvm(
    admin_queue: &AdminQueue,
    nsid: u32,
    lbaf: u8,
    secure_erase: u8,
    protection_info: u8,
    metadata_location: bool,
) -> Result<(), NvmeError> {
    let mut cmd = SubmissionEntry::new();
    cmd.set_opcode(ADMIN_OPC_FORMAT_NVM);
    cmd.nsid = nsid;

    let mut cdw10: u32 = 0;
    cdw10 |= (lbaf & 0x0F) as u32;
    cdw10 |= ((metadata_location as u32) & 0x1) << 4;
    cdw10 |= ((protection_info & 0x07) as u32) << 5;
    cdw10 |= ((secure_erase & 0x07) as u32) << 9;
    cmd.cdw10 = cdw10;

    let _completion = admin_queue.submit_and_wait(cmd)?;
    Ok(())
}
