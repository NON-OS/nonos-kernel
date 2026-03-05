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

impl IoResult {
    /// Get operation status
    pub fn status(&self) -> IoStatus {
        self.status
    }

    /// Get bytes transferred
    pub fn bytes_transferred(&self) -> usize {
        self.bytes_transferred
    }

    /// Get error code
    pub fn error_code(&self) -> u32 {
        self.error_code
    }

    /// Get completion time
    pub fn completion_time(&self) -> u64 {
        self.completion_time
    }

    /// Check if operation succeeded
    pub fn is_success(&self) -> bool {
        matches!(self.status, IoStatus::Success | IoStatus::Completed)
    }
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

impl DeviceInfo {
    /// Get device type
    pub fn device_type(&self) -> StorageType {
        self.device_type
    }

    /// Get model name
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Get vendor name
    pub fn vendor(&self) -> &str {
        &self.vendor
    }

    /// Get serial number
    pub fn serial(&self) -> &str {
        &self.serial
    }

    /// Get firmware name
    pub fn firmware(&self) -> &str {
        &self.firmware
    }

    /// Get firmware version
    pub fn firmware_version(&self) -> &str {
        &self.firmware_version
    }

    /// Get capacity in sectors/blocks
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Get capacity in bytes
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    /// Get block size
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Get max transfer size
    pub fn max_transfer_size(&self) -> usize {
        self.max_transfer_size
    }

    /// Get max queue depth
    pub fn max_queue_depth(&self) -> u32 {
        self.max_queue_depth
    }

    /// Get device capabilities
    pub fn features(&self) -> DeviceCapabilities {
        self.features
    }

    /// Check if device supports a capability
    pub fn supports(&self, cap: DeviceCapabilities) -> bool {
        self.features.contains(cap)
    }
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

impl SmartData {
    /// Get temperature in Celsius
    pub fn temperature_celsius(&self) -> u16 {
        self.temperature
    }

    /// Get power on hours
    pub fn power_on_hours(&self) -> u32 {
        self.power_on_hours
    }

    /// Get power cycle count
    pub fn power_cycles(&self) -> u64 {
        self.power_cycles
    }

    /// Get unsafe shutdown count
    pub fn unsafe_shutdowns(&self) -> u64 {
        self.unsafe_shutdowns
    }

    /// Get media error count
    pub fn media_errors(&self) -> u64 {
        self.media_errors
    }

    /// Get error log entries
    pub fn error_log_entries(&self) -> u64 {
        self.error_log_entries
    }

    /// Check if there's a critical warning
    pub fn has_critical_warning(&self) -> bool {
        self.critical_warning != 0
    }

    /// Get available spare percentage
    pub fn available_spare(&self) -> u8 {
        self.available_spare
    }

    /// Get available spare threshold
    pub fn spare_threshold(&self) -> u8 {
        self.available_spare_threshold
    }

    /// Check if spare is below threshold
    pub fn is_spare_low(&self) -> bool {
        self.available_spare < self.available_spare_threshold
    }

    /// Get percentage used
    pub fn percentage_used(&self) -> u8 {
        self.percentage_used
    }

    /// Get total data read in units
    pub fn data_units_read(&self) -> u64 {
        self.data_units_read
    }

    /// Get total data written in units
    pub fn data_units_written(&self) -> u64 {
        self.data_units_written
    }

    /// Get host read commands
    pub fn read_commands(&self) -> u64 {
        self.host_read_commands
    }

    /// Get host write commands
    pub fn write_commands(&self) -> u64 {
        self.host_write_commands
    }

    /// Get reallocated sector count
    pub fn reallocated_sectors(&self) -> u32 {
        self.reallocated_sectors
    }

    /// Get pending sector count
    pub fn pending_sectors(&self) -> u32 {
        self.pending_sectors
    }

    /// Get health status
    pub fn health_status(&self) -> u8 {
        self.health_status
    }

    /// Check if drive is healthy
    pub fn is_healthy(&self) -> bool {
        self.health_status == 0 && !self.has_critical_warning()
    }
}
