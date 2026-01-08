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

use alloc::vec::Vec;
use super::super::constants::*;
use super::super::error::NvmeError;
use super::super::types::{SubmissionEntry, ControllerIdentity};
use super::super::dma::DmaRegion;
use super::super::queue::AdminQueue;
use super::super::namespace::{Namespace, parse_namespace_list};

pub fn identify_controller(
    admin_queue: &AdminQueue,
) -> Result<ControllerIdentity, NvmeError> {
    let buffer = DmaRegion::allocate(IDENTIFY_DATA_SIZE)?;

    let cmd = SubmissionEntry::build_identify(
        0,
        0,
        CNS_CONTROLLER,
        buffer.phys_u64(),
    );

    let _completion = admin_queue.submit_and_wait(cmd)?;

    // SAFETY: buffer is valid DMA region with 4096 bytes
    let data: &[u8; 4096] = unsafe {
        &*(buffer.as_ptr::<[u8; 4096]>())
    };

    Ok(ControllerIdentity::from_data(data))
}

pub fn get_active_namespace_list(
    admin_queue: &AdminQueue,
    start_nsid: u32,
) -> Result<Vec<u32>, NvmeError> {
    let buffer = DmaRegion::allocate(NS_LIST_SIZE)?;
    let cmd = SubmissionEntry::build_identify(
        0,
        start_nsid,
        CNS_ACTIVE_NS_LIST,
        buffer.phys_u64(),
    );

    let _completion = admin_queue.submit_and_wait(cmd)?;
    // SAFETY: buffer is valid DMA region with 4096 bytes
    let data: &[u8; 4096] = unsafe {
        &*(buffer.as_ptr::<[u8; 4096]>())
    };

    Ok(parse_namespace_list(data))
}

pub fn identify_namespace(
    admin_queue: &AdminQueue,
    nsid: u32,
) -> Result<Namespace, NvmeError> {
    if nsid == 0 {
        return Err(NvmeError::InvalidNamespaceId);
    }

    let buffer = DmaRegion::allocate(IDENTIFY_DATA_SIZE)?;
    let cmd = SubmissionEntry::build_identify(
        0,
        nsid,
        CNS_NAMESPACE,
        buffer.phys_u64(),
    );

    let _completion = admin_queue.submit_and_wait(cmd)?;
    // SAFETY: buffer is valid DMA region with 4096 bytes
    let data: &[u8; 4096] = unsafe {
        &*(buffer.as_ptr::<[u8; 4096]>())
    };

    Namespace::from_identify_data(nsid, data)
}

pub fn create_io_completion_queue(
    admin_queue: &AdminQueue,
    qid: u16,
    qsize: u16,
    queue_phys: u64,
    irq_vector: u16,
    irq_enabled: bool,
) -> Result<(), NvmeError> {
    if qid == 0 {
        return Err(NvmeError::InvalidQueueSize);
    }

    let cmd = SubmissionEntry::build_create_cq(
        0,
        qid,
        qsize,
        queue_phys,
        irq_vector,
        irq_enabled,
    );

    let _completion = admin_queue.submit_and_wait(cmd)?;
    Ok(())
}

pub fn create_io_submission_queue(
    admin_queue: &AdminQueue,
    qid: u16,
    qsize: u16,
    queue_phys: u64,
    cqid: u16,
    priority: u8,
) -> Result<(), NvmeError> {
    if qid == 0 {
        return Err(NvmeError::InvalidQueueSize);
    }

    let cmd = SubmissionEntry::build_create_sq(
        0,
        qid,
        qsize,
        queue_phys,
        cqid,
        priority,
    );

    let _completion = admin_queue.submit_and_wait(cmd)?;
    Ok(())
}

pub fn delete_io_submission_queue(
    admin_queue: &AdminQueue,
    qid: u16,
) -> Result<(), NvmeError> {
    if qid == 0 {
        return Err(NvmeError::InvalidQueueSize);
    }

    let mut cmd = SubmissionEntry::new();
    cmd.set_opcode(ADMIN_OPC_DELETE_SQ);
    cmd.cdw10 = qid as u32;
    let _completion = admin_queue.submit_and_wait(cmd)?;
    Ok(())
}

pub fn delete_io_completion_queue(
    admin_queue: &AdminQueue,
    qid: u16,
) -> Result<(), NvmeError> {
    if qid == 0 {
        return Err(NvmeError::InvalidQueueSize);
    }

    let mut cmd = SubmissionEntry::new();
    cmd.set_opcode(ADMIN_OPC_DELETE_CQ);
    cmd.cdw10 = qid as u32;
    let _completion = admin_queue.submit_and_wait(cmd)?;
    Ok(())
}

pub fn get_feature(
    admin_queue: &AdminQueue,
    fid: u8,
    nsid: u32,
) -> Result<u32, NvmeError> {
    let cmd = SubmissionEntry::build_get_features(0, fid, nsid);
    let completion = admin_queue.submit_and_wait(cmd)?;
    Ok(completion.dw0)
}

pub fn set_feature(
    admin_queue: &AdminQueue,
    fid: u8,
    nsid: u32,
    value: u32,
) -> Result<(), NvmeError> {
    let cmd = SubmissionEntry::build_set_features(0, fid, nsid, value);
    let _completion = admin_queue.submit_and_wait(cmd)?;
    Ok(())
}

pub fn get_number_of_queues(admin_queue: &AdminQueue) -> Result<(u16, u16), NvmeError> {
    let result = get_feature(admin_queue, FID_NUM_QUEUES, 0)?;
    let nsqa = (result & 0xFFFF) as u16;
    let ncqa = ((result >> 16) & 0xFFFF) as u16;
    Ok((nsqa + 1, ncqa + 1))
}

pub fn set_number_of_queues(
    admin_queue: &AdminQueue,
    num_sq: u16,
    num_cq: u16,
) -> Result<(u16, u16), NvmeError> {
    let nsqr = num_sq.saturating_sub(1) as u32;
    let ncqr = num_cq.saturating_sub(1) as u32;
    let value = nsqr | (ncqr << 16);

    let cmd = SubmissionEntry::build_set_features(0, FID_NUM_QUEUES, 0, value);
    let completion = admin_queue.submit_and_wait(cmd)?;
    let nsqa = (completion.dw0 & 0xFFFF) as u16;
    let ncqa = ((completion.dw0 >> 16) & 0xFFFF) as u16;
    Ok((nsqa + 1, ncqa + 1))
}

pub fn abort_command(
    admin_queue: &AdminQueue,
    sqid: u16,
    cid: u16,
) -> Result<bool, NvmeError> {
    let cmd = SubmissionEntry::build_abort(0, sqid, cid);
    let completion = admin_queue.submit_and_wait(cmd)?;
    let aborted = (completion.dw0 & 0x1) == 0;
    Ok(aborted)
}

pub fn get_log_page(
    admin_queue: &AdminQueue,
    lid: u8,
    nsid: u32,
    buffer_size: usize,
) -> Result<DmaRegion, NvmeError> {
    let buffer = DmaRegion::allocate(buffer_size)?;
    let numdl = ((buffer_size / 4) - 1) as u16;
    let cmd = SubmissionEntry::build_get_log_page(
        0,
        nsid,
        lid,
        numdl,
        buffer.phys_u64(),
    );

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
