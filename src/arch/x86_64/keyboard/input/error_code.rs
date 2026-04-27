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
#[repr(u32)]
pub enum InputErrorCode {
    QueueFull = 1,
    QueueEmpty = 2,
    InvalidEvent = 3,
    InvalidConfig = 4,
    DeviceNotFound = 5,
    Timeout = 6,
    InternalError = 7,
    QueueShutdown = 8,
    FilterRejected = 9,
    ResourceExhausted = 10,
}

impl InputErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueueFull => "input queue is full",
            Self::QueueEmpty => "input queue is empty",
            Self::InvalidEvent => "invalid event data",
            Self::InvalidConfig => "invalid configuration parameter",
            Self::DeviceNotFound => "input device not found",
            Self::Timeout => "operation timed out",
            Self::InternalError => "internal error",
            Self::QueueShutdown => "queue has been shutdown",
            Self::FilterRejected => "event rejected by filter",
            Self::ResourceExhausted => "resource exhausted",
        }
    }

    pub const fn code(self) -> u32 {
        self as u32
    }
}
