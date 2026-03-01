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

use super::state::MscDeviceState;
use super::constants::*;
use super::sense::SenseData;
use super::inquiry::InquiryResponse;
use super::capacity::StorageCapacity;
use super::scsi::send_scsi_command;

pub fn test_unit_ready(state: &MscDeviceState) -> Result<bool, &'static str> {
    let cmd = [SCSI_TEST_UNIT_READY, 0, 0, 0, 0, 0];
    let csw = send_scsi_command(state, &cmd, None, None)?;
    Ok(csw.passed())
}

pub fn request_sense(state: &MscDeviceState) -> Result<SenseData, &'static str> {
    let cmd = [SCSI_REQUEST_SENSE, 0, 0, 0, 18, 0];
    let mut data = [0u8; 18];

    let csw = send_scsi_command(state, &cmd, Some(&mut data), None)?;
    if !csw.passed() {
        return Err("Request sense failed");
    }

    SenseData::parse(&data).ok_or("Invalid sense data")
}

pub fn inquiry(state: &MscDeviceState) -> Result<InquiryResponse, &'static str> {
    let cmd = [SCSI_INQUIRY, 0, 0, 0, 36, 0];
    let mut data = [0u8; 36];

    let csw = send_scsi_command(state, &cmd, Some(&mut data), None)?;
    if !csw.passed() {
        return Err("Inquiry failed");
    }

    InquiryResponse::parse(&data).ok_or("Invalid inquiry response")
}

pub fn read_capacity_10(state: &MscDeviceState) -> Result<StorageCapacity, &'static str> {
    let cmd = [SCSI_READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut data = [0u8; 8];

    let csw = send_scsi_command(state, &cmd, Some(&mut data), None)?;
    if !csw.passed() {
        return Err("Read capacity (10) failed");
    }

    let last_lba = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64;
    let block_size = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    let total_blocks = last_lba + 1;
    let total_bytes = total_blocks * block_size as u64;

    Ok(StorageCapacity {
        total_blocks,
        block_size,
        total_bytes,
    })
}

pub fn read_capacity_16(state: &MscDeviceState) -> Result<StorageCapacity, &'static str> {
    let cmd = [SCSI_READ_CAPACITY_16, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0];
    let mut data = [0u8; 32];

    let csw = send_scsi_command(state, &cmd, Some(&mut data), None)?;
    if !csw.passed() {
        return Err("Read capacity (16) failed");
    }

    let last_lba = u64::from_be_bytes([
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7],
    ]);
    let block_size = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    let total_blocks = last_lba + 1;
    let total_bytes = total_blocks * block_size as u64;

    Ok(StorageCapacity {
        total_blocks,
        block_size,
        total_bytes,
    })
}

pub fn get_capacity(state: &MscDeviceState) -> Result<StorageCapacity, &'static str> {
    match read_capacity_10(state) {
        Ok(cap) => {
            if cap.total_blocks >= 0xFFFFFFFF {
                read_capacity_16(state)
            } else {
                Ok(cap)
            }
        }
        Err(_) => {
            read_capacity_16(state)
        }
    }
}

pub fn read_blocks(
    state: &MscDeviceState,
    lba: u64,
    block_count: u16,
    buffer: &mut [u8],
) -> Result<usize, &'static str> {
    if lba > 0xFFFFFFFF {
        return Err("LBA too large for READ(10)");
    }

    let lba_bytes = (lba as u32).to_be_bytes();
    let count_bytes = block_count.to_be_bytes();

    let cmd = [
        SCSI_READ_10,
        0,
        lba_bytes[0], lba_bytes[1], lba_bytes[2], lba_bytes[3],
        0,
        count_bytes[0], count_bytes[1],
        0,
    ];

    let csw = send_scsi_command(state, &cmd, Some(buffer), None)?;
    if !csw.passed() {
        return Err("Read failed");
    }

    Ok(buffer.len() - csw.d_csw_data_residue as usize)
}

pub fn write_blocks(
    state: &MscDeviceState,
    lba: u64,
    block_count: u16,
    data: &[u8],
) -> Result<usize, &'static str> {
    if lba > 0xFFFFFFFF {
        return Err("LBA too large for WRITE(10)");
    }

    let lba_bytes = (lba as u32).to_be_bytes();
    let count_bytes = block_count.to_be_bytes();

    let cmd = [
        SCSI_WRITE_10,
        0,
        lba_bytes[0], lba_bytes[1], lba_bytes[2], lba_bytes[3],
        0,
        count_bytes[0], count_bytes[1],
        0,
    ];

    let csw = send_scsi_command(state, &cmd, None, Some(data))?;
    if !csw.passed() {
        return Err("Write failed");
    }

    Ok(data.len() - csw.d_csw_data_residue as usize)
}

pub fn read_blocks_16(
    state: &MscDeviceState,
    lba: u64,
    block_count: u32,
    buffer: &mut [u8],
) -> Result<usize, &'static str> {
    let lba_bytes = lba.to_be_bytes();
    let count_bytes = block_count.to_be_bytes();

    let cmd = [
        SCSI_READ_16,
        0,
        lba_bytes[0], lba_bytes[1], lba_bytes[2], lba_bytes[3],
        lba_bytes[4], lba_bytes[5], lba_bytes[6], lba_bytes[7],
        count_bytes[0], count_bytes[1], count_bytes[2], count_bytes[3],
        0, 0,
    ];

    let csw = send_scsi_command(state, &cmd, Some(buffer), None)?;
    if !csw.passed() {
        return Err("Read(16) failed");
    }

    Ok(buffer.len() - csw.d_csw_data_residue as usize)
}

pub fn write_blocks_16(
    state: &MscDeviceState,
    lba: u64,
    block_count: u32,
    data: &[u8],
) -> Result<usize, &'static str> {
    let lba_bytes = lba.to_be_bytes();
    let count_bytes = block_count.to_be_bytes();

    let cmd = [
        SCSI_WRITE_16,
        0,
        lba_bytes[0], lba_bytes[1], lba_bytes[2], lba_bytes[3],
        lba_bytes[4], lba_bytes[5], lba_bytes[6], lba_bytes[7],
        count_bytes[0], count_bytes[1], count_bytes[2], count_bytes[3],
        0, 0,
    ];

    let csw = send_scsi_command(state, &cmd, None, Some(data))?;
    if !csw.passed() {
        return Err("Write(16) failed");
    }

    Ok(data.len() - csw.d_csw_data_residue as usize)
}

pub fn sync_cache(state: &MscDeviceState) -> Result<(), &'static str> {
    let cmd = [SCSI_SYNCHRONIZE_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let csw = send_scsi_command(state, &cmd, None, None)?;
    if !csw.passed() {
        return Err("Sync cache failed");
    }
    Ok(())
}

pub fn is_write_protected(state: &MscDeviceState) -> Result<bool, &'static str> {
    let cmd = [SCSI_MODE_SENSE_6, 0, 0x3F, 0, 192, 0];
    let mut data = [0u8; 192];

    let csw = send_scsi_command(state, &cmd, Some(&mut data), None)?;
    if !csw.passed() {
        return Ok(false);
    }

    let device_specific = data[2];
    Ok((device_specific & 0x80) != 0)
}

pub fn eject_media(state: &MscDeviceState, eject: bool) -> Result<(), &'static str> {
    let cmd = [
        SCSI_START_STOP_UNIT,
        0,
        0,
        0,
        if eject { 0x02 } else { 0x03 },
        0,
    ];

    let csw = send_scsi_command(state, &cmd, None, None)?;
    if !csw.passed() {
        return Err("Start/stop unit failed");
    }
    Ok(())
}

pub fn lock_media(state: &MscDeviceState, lock: bool) -> Result<(), &'static str> {
    let cmd = [
        SCSI_PREVENT_ALLOW_MEDIUM_REMOVAL,
        0,
        0,
        0,
        if lock { 0x01 } else { 0x00 },
        0,
    ];

    let csw = send_scsi_command(state, &cmd, None, None)?;
    if !csw.passed() {
        return Err("Prevent/allow medium removal failed");
    }
    Ok(())
}

pub fn read_blocks_auto(
    state: &MscDeviceState,
    lba: u64,
    block_count: u32,
    buffer: &mut [u8],
) -> Result<usize, &'static str> {
    if lba > 0xFFFFFFFF || block_count > 0xFFFF {
        read_blocks_16(state, lba, block_count, buffer)
    } else {
        read_blocks(state, lba, block_count as u16, buffer)
    }
}

pub fn write_blocks_auto(
    state: &MscDeviceState,
    lba: u64,
    block_count: u32,
    data: &[u8],
) -> Result<usize, &'static str> {
    if lba > 0xFFFFFFFF || block_count > 0xFFFF {
        write_blocks_16(state, lba, block_count, data)
    } else {
        write_blocks(state, lba, block_count as u16, data)
    }
}
