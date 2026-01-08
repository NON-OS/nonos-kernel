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

use core::fmt;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyboardError {
    ControllerNotResponding,
    SelfTestFailed,
    DeviceNotPresent,
    CommandTimeout,
    AckTimeout,
    BufferFull,
    InvalidScancode,
    LedUpdateFailed,
    ResetFailed,
    SetScancodeSetFailed,
    EnableFailed,
    DisableFailed,
}

impl KeyboardError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ControllerNotResponding => "Keyboard controller not responding",
            Self::SelfTestFailed => "Keyboard self-test failed",
            Self::DeviceNotPresent => "Keyboard device not present",
            Self::CommandTimeout => "Command timeout",
            Self::AckTimeout => "ACK timeout",
            Self::BufferFull => "Input buffer full",
            Self::InvalidScancode => "Invalid scancode received",
            Self::LedUpdateFailed => "LED update failed",
            Self::ResetFailed => "Keyboard reset failed",
            Self::SetScancodeSetFailed => "Failed to set scancode set",
            Self::EnableFailed => "Failed to enable keyboard",
            Self::DisableFailed => "Failed to disable keyboard",
        }
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::BufferFull | Self::AckTimeout | Self::CommandTimeout
        )
    }
}

impl fmt::Display for KeyboardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type Result<T> = core::result::Result<T, KeyboardError>;
