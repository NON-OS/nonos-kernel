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
pub enum SignalError {
    InvalidSignal,
    InvalidHandler,
    PermissionDenied,
    ProcessNotFound,
    QueueFull,
    Interrupted,
    Timeout,
    NoMemory,
    BadAddress,
    Again,
}

impl SignalError {
    pub fn as_errno(&self) -> i32 {
        match self {
            Self::InvalidSignal => -22,
            Self::InvalidHandler => -22,
            Self::PermissionDenied => -1,
            Self::ProcessNotFound => -3,
            Self::QueueFull => -11,
            Self::Interrupted => -4,
            Self::Timeout => -110,
            Self::NoMemory => -12,
            Self::BadAddress => -14,
            Self::Again => -11,
        }
    }
}
