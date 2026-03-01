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

pub(super) const SCSI_TEST_UNIT_READY: u8 = 0x00;
pub(super) const SCSI_REQUEST_SENSE: u8 = 0x03;
pub(super) const SCSI_INQUIRY: u8 = 0x12;
pub(super) const SCSI_READ_CAPACITY_10: u8 = 0x25;
pub(super) const SCSI_READ_10: u8 = 0x28;
pub(super) const SCSI_WRITE_10: u8 = 0x2A;
pub(super) const SCSI_READ_CAPACITY_16: u8 = 0x9E;
pub(super) const SCSI_READ_16: u8 = 0x88;
pub(super) const SCSI_WRITE_16: u8 = 0x8A;
pub(super) const SCSI_SYNCHRONIZE_CACHE_10: u8 = 0x35;
pub(super) const SCSI_MODE_SENSE_6: u8 = 0x1A;
pub(super) const SCSI_START_STOP_UNIT: u8 = 0x1B;
pub(super) const SCSI_PREVENT_ALLOW_MEDIUM_REMOVAL: u8 = 0x1E;

pub(super) const CBW_SIGNATURE: u32 = 0x43425355;
pub(super) const CSW_SIGNATURE: u32 = 0x53425355;

pub(super) const CBW_FLAG_DATA_IN: u8 = 0x80;
pub(super) const CBW_FLAG_DATA_OUT: u8 = 0x00;

pub(super) const CSW_STATUS_PASSED: u8 = 0x00;
