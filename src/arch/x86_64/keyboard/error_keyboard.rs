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
pub enum KeyboardError {
    NotInitialized, AlreadyInitialized, NoDevicesDetected, Timeout, DeviceNotResponding,
    InvalidCommand, BufferFull, BufferEmpty, InvalidScanCode, InvalidLayout, QueueFull,
    QueueEmpty, DeviceNotFound, UnsupportedDevice, CommunicationError, SelfTestFailed,
}

impl KeyboardError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "keyboard not initialized", Self::AlreadyInitialized => "keyboard already initialized",
            Self::NoDevicesDetected => "no keyboard devices detected", Self::Timeout => "keyboard operation timed out",
            Self::DeviceNotResponding => "keyboard device not responding", Self::InvalidCommand => "invalid keyboard command",
            Self::BufferFull => "keyboard buffer full", Self::BufferEmpty => "keyboard buffer empty",
            Self::InvalidScanCode => "invalid scan code", Self::InvalidLayout => "invalid keyboard layout",
            Self::QueueFull => "event queue full", Self::QueueEmpty => "event queue empty",
            Self::DeviceNotFound => "keyboard device not found", Self::UnsupportedDevice => "unsupported keyboard device",
            Self::CommunicationError => "keyboard communication error", Self::SelfTestFailed => "keyboard self-test failed",
        }
    }
    pub const fn code(self) -> u8 {
        match self {
            Self::NotInitialized => 1, Self::AlreadyInitialized => 2, Self::NoDevicesDetected => 3, Self::Timeout => 4,
            Self::DeviceNotResponding => 5, Self::InvalidCommand => 6, Self::BufferFull => 7, Self::BufferEmpty => 8,
            Self::InvalidScanCode => 9, Self::InvalidLayout => 10, Self::QueueFull => 11, Self::QueueEmpty => 12,
            Self::DeviceNotFound => 13, Self::UnsupportedDevice => 14, Self::CommunicationError => 15, Self::SelfTestFailed => 16,
        }
    }
}

pub type KeyboardResult<T> = Result<T, KeyboardError>;
