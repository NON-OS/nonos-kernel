// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.


pub(super) const SCSI_TEST_UNIT_READY: u8 = 0x00;
pub(super) const SCSI_READ_CAPACITY_10: u8 = 0x25;
pub(super) const SCSI_READ_10: u8 = 0x28;
pub(super) const SCSI_WRITE_10: u8 = 0x2A;

pub(super) fn build_test_unit_ready() -> [u8; 6] {
    let mut cmd = [0u8; 6];
    cmd[0] = SCSI_TEST_UNIT_READY;
    cmd
}

pub(super) fn build_read_capacity_10() -> [u8; 10] {
    let mut cmd = [0u8; 10];
    cmd[0] = SCSI_READ_CAPACITY_10;
    cmd
}

pub(super) fn build_read_10(lba: u32, block_count: u16) -> [u8; 10] {
    let mut cmd = [0u8; 10];
    cmd[0] = SCSI_READ_10;
    cmd[2..6].copy_from_slice(&lba.to_be_bytes());
    cmd[7..9].copy_from_slice(&block_count.to_be_bytes());
    cmd
}

pub(super) fn build_write_10(lba: u32, block_count: u16) -> [u8; 10] {
    let mut cmd = [0u8; 10];
    cmd[0] = SCSI_WRITE_10;
    cmd[2..6].copy_from_slice(&lba.to_be_bytes());
    cmd[7..9].copy_from_slice(&block_count.to_be_bytes());
    cmd
}
