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
