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


extern crate alloc;

use alloc::string::String;
use x86_64::VirtAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageType {
    Hdd,
    Ssd,
    Nvme,
    UsbMass,
    RamDisk,
    Network,
    VirtualDisk,
    Unknown,
}

impl Default for StorageType {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerState {
    Active,
    Idle,
    Standby,
    Sleep,
    Off,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoOperation {
    Read,
    Write,
    Flush,
    Trim,
    SecureErase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoStatus {
    Pending,
    InProgress,
    Completed,
    Success,
    Failed,
    Cancelled,
    InvalidRequest,
    Timeout,
    DeviceError,
}

impl Default for IoStatus {
    fn default() -> Self {
        Self::Pending
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoError {
    InvalidOffset,
    InvalidLength,
    InvalidRequest,
    DeviceError,
    Timeout,
    NotReady,
    NoSpace,
    ReadOnly,
    NotSupported,
    Busy,
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct IoFlags: u32 {
        const NONE = 0;
        const SYNC = 1 << 0;
        const DIRECT = 1 << 1;
        const FUA = 1 << 2;
        const PRIORITY_HIGH = 1 << 3;
        const PRIORITY_LOW = 1 << 4;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct DeviceCapabilities: u32 {
        const NONE = 0;
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const FLUSH = 1 << 2;
        const TRIM = 1 << 3;
        const SECURE_ERASE = 1 << 4;
        const NCQ = 1 << 5;
        const FUA = 1 << 6;
        const ENCRYPTION = 1 << 7;
        const SMART = 1 << 8;
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IoResult {
    pub status: IoStatus,
    pub bytes_transferred: usize,
    pub error_code: u32,
    pub completion_time: u64,
}

pub type IoCompletionCallback = fn(IoResult);

#[derive(Clone)]
pub struct IoRequest {
    pub operation: IoOperation,
    pub lba: u64,
    pub block_count: u32,
    pub buffer: VirtAddr,
    pub buffer_size: usize,
    pub flags: IoFlags,
    pub status: IoStatus,
    pub priority: u8,
    pub request_id: u64,
    pub timestamp: u64,
    pub completion_callback: Option<IoCompletionCallback>,
}

impl core::fmt::Debug for IoRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IoRequest")
            .field("operation", &self.operation)
            .field("lba", &self.lba)
            .field("block_count", &self.block_count)
            .field("buffer_size", &self.buffer_size)
            .field("flags", &self.flags)
            .field("status", &self.status)
            .field("priority", &self.priority)
            .field("request_id", &self.request_id)
            .finish()
    }
}

impl Default for IoRequest {
    fn default() -> Self {
        Self {
            operation: IoOperation::Read,
            lba: 0,
            block_count: 0,
            buffer: VirtAddr::zero(),
            buffer_size: 0,
            flags: IoFlags::NONE,
            status: IoStatus::Pending,
            priority: 0,
            request_id: 0,
            timestamp: 0,
            completion_callback: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DeviceInfo {
    pub device_type: StorageType,
    pub model: String,
    pub vendor: String,
    pub serial: String,
    pub firmware: String,
    pub firmware_version: String,
    pub capacity: u64,
    pub capacity_bytes: u64,
    pub block_size: u32,
    pub max_transfer_size: usize,
    pub max_queue_depth: u32,
    pub features: DeviceCapabilities,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SmartData {
    pub temperature: u16,
    pub power_on_hours: u32,
    pub power_cycles: u64,
    pub unsafe_shutdowns: u64,
    pub media_errors: u64,
    pub error_log_entries: u64,
    pub critical_warning: u8,
    pub available_spare: u8,
    pub available_spare_threshold: u8,
    pub percentage_used: u8,
    pub data_units_read: u64,
    pub data_units_written: u64,
    pub host_read_commands: u64,
    pub host_write_commands: u64,
    pub reallocated_sectors: u32,
    pub pending_sectors: u32,
    pub health_status: u8,
}
