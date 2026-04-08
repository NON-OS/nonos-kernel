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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbHidError {
    NotInitialized, AlreadyInitialized, NoDevices, DeviceNotFound, InvalidEndpoint,
    TransferFailed, InvalidReport, UnsupportedProtocol, BufferTooSmall, Timeout, Stalled, Disconnected,
}

impl UsbHidError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "USB HID not initialized", Self::AlreadyInitialized => "USB HID already initialized",
            Self::NoDevices => "no USB HID devices found", Self::DeviceNotFound => "USB HID device not found",
            Self::InvalidEndpoint => "invalid USB endpoint", Self::TransferFailed => "USB transfer failed",
            Self::InvalidReport => "invalid HID report", Self::UnsupportedProtocol => "unsupported HID protocol",
            Self::BufferTooSmall => "buffer too small", Self::Timeout => "USB operation timed out",
            Self::Stalled => "USB endpoint stalled", Self::Disconnected => "USB device disconnected",
        }
    }
}

pub type UsbHidResult<T> = Result<T, UsbHidError>;
