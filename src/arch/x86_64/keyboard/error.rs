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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyboardError {
    NotInitialized,
    AlreadyInitialized,
    NoDevicesDetected,
    Timeout,
    DeviceNotResponding,
    InvalidCommand,
    BufferFull,
    BufferEmpty,
    InvalidScanCode,
    InvalidLayout,
    QueueFull,
    QueueEmpty,
    DeviceNotFound,
    UnsupportedDevice,
    CommunicationError,
    SelfTestFailed,
}

impl KeyboardError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "keyboard not initialized",
            Self::AlreadyInitialized => "keyboard already initialized",
            Self::NoDevicesDetected => "no keyboard devices detected",
            Self::Timeout => "keyboard operation timed out",
            Self::DeviceNotResponding => "keyboard device not responding",
            Self::InvalidCommand => "invalid keyboard command",
            Self::BufferFull => "keyboard buffer full",
            Self::BufferEmpty => "keyboard buffer empty",
            Self::InvalidScanCode => "invalid scan code",
            Self::InvalidLayout => "invalid keyboard layout",
            Self::QueueFull => "event queue full",
            Self::QueueEmpty => "event queue empty",
            Self::DeviceNotFound => "keyboard device not found",
            Self::UnsupportedDevice => "unsupported keyboard device",
            Self::CommunicationError => "keyboard communication error",
            Self::SelfTestFailed => "keyboard self-test failed",
        }
    }

    pub const fn code(self) -> u8 {
        match self {
            Self::NotInitialized => 1,
            Self::AlreadyInitialized => 2,
            Self::NoDevicesDetected => 3,
            Self::Timeout => 4,
            Self::DeviceNotResponding => 5,
            Self::InvalidCommand => 6,
            Self::BufferFull => 7,
            Self::BufferEmpty => 8,
            Self::InvalidScanCode => 9,
            Self::InvalidLayout => 10,
            Self::QueueFull => 11,
            Self::QueueEmpty => 12,
            Self::DeviceNotFound => 13,
            Self::UnsupportedDevice => 14,
            Self::CommunicationError => 15,
            Self::SelfTestFailed => 16,
        }
    }
}

pub type KeyboardResult<T> = Result<T, KeyboardError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ps2Error {
    NotInitialized,
    AlreadyInitialized,
    ControllerNotFound,
    Timeout,
    SelfTestFailed,
    Port1TestFailed,
    Port2TestFailed,
    KeyboardNotDetected,
    MouseNotDetected,
    SendFailed,
    InvalidResponse,
    BufferOverrun,
    ParityError,
    GeneralError,
}

impl Ps2Error {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "PS/2 not initialized",
            Self::AlreadyInitialized => "PS/2 already initialized",
            Self::ControllerNotFound => "PS/2 controller not found",
            Self::Timeout => "PS/2 operation timed out",
            Self::SelfTestFailed => "PS/2 self-test failed",
            Self::Port1TestFailed => "PS/2 port 1 test failed",
            Self::Port2TestFailed => "PS/2 port 2 test failed",
            Self::KeyboardNotDetected => "PS/2 keyboard not detected",
            Self::MouseNotDetected => "PS/2 mouse not detected",
            Self::SendFailed => "PS/2 send command failed",
            Self::InvalidResponse => "PS/2 invalid response",
            Self::BufferOverrun => "PS/2 buffer overrun",
            Self::ParityError => "PS/2 parity error",
            Self::GeneralError => "PS/2 general error",
        }
    }
}

pub type Ps2Result<T> = Result<T, Ps2Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbHidError {
    NotInitialized,
    AlreadyInitialized,
    NoDevices,
    DeviceNotFound,
    InvalidEndpoint,
    TransferFailed,
    InvalidReport,
    UnsupportedProtocol,
    BufferTooSmall,
    Timeout,
    Stalled,
    Disconnected,
}

impl UsbHidError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "USB HID not initialized",
            Self::AlreadyInitialized => "USB HID already initialized",
            Self::NoDevices => "no USB HID devices found",
            Self::DeviceNotFound => "USB HID device not found",
            Self::InvalidEndpoint => "invalid USB endpoint",
            Self::TransferFailed => "USB transfer failed",
            Self::InvalidReport => "invalid HID report",
            Self::UnsupportedProtocol => "unsupported HID protocol",
            Self::BufferTooSmall => "buffer too small",
            Self::Timeout => "USB operation timed out",
            Self::Stalled => "USB endpoint stalled",
            Self::Disconnected => "USB device disconnected",
        }
    }
}

pub type UsbHidResult<T> = Result<T, UsbHidError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    NotFound,
    InvalidId,
    RegistryFull,
    AlreadyRegistered,
    InvalidScanCode,
}

impl LayoutError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "layout not found",
            Self::InvalidId => "invalid layout ID",
            Self::RegistryFull => "custom layout registry full",
            Self::AlreadyRegistered => "layout already registered",
            Self::InvalidScanCode => "invalid scan code",
        }
    }
}

pub type LayoutResult<T> = Result<T, LayoutError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputError {
    QueueFull,
    QueueEmpty,
    DeviceNotRegistered,
    DeviceLimitReached,
    InvalidDeviceId,
    FilterRejected,
}

impl InputError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueueFull => "input queue full",
            Self::QueueEmpty => "input queue empty",
            Self::DeviceNotRegistered => "input device not registered",
            Self::DeviceLimitReached => "input device limit reached",
            Self::InvalidDeviceId => "invalid device ID",
            Self::FilterRejected => "event rejected by filter",
        }
    }
}

pub type InputResult<T> = Result<T, InputError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeymapError {
    InvalidScanCode,
    IncompleteExtended,
    UnknownExtended,
    PendingDeadKey,
    InvalidCompose,
}

impl KeymapError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidScanCode => "invalid scan code",
            Self::IncompleteExtended => "incomplete extended scan code",
            Self::UnknownExtended => "unknown extended scan code",
            Self::PendingDeadKey => "dead key sequence pending",
            Self::InvalidCompose => "invalid compose sequence",
        }
    }
}

pub type KeymapResult<T> = Result<T, KeymapError>;
