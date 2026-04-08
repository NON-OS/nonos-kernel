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
pub enum LayoutError { NotFound, InvalidId, RegistryFull, AlreadyRegistered, InvalidScanCode }

impl LayoutError {
    pub const fn as_str(self) -> &'static str {
        match self { Self::NotFound => "layout not found", Self::InvalidId => "invalid layout ID", Self::RegistryFull => "custom layout registry full", Self::AlreadyRegistered => "layout already registered", Self::InvalidScanCode => "invalid scan code" }
    }
}

pub type LayoutResult<T> = Result<T, LayoutError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputError { QueueFull, QueueEmpty, DeviceNotRegistered, DeviceLimitReached, InvalidDeviceId, FilterRejected }

impl InputError {
    pub const fn as_str(self) -> &'static str {
        match self { Self::QueueFull => "input queue full", Self::QueueEmpty => "input queue empty", Self::DeviceNotRegistered => "input device not registered", Self::DeviceLimitReached => "input device limit reached", Self::InvalidDeviceId => "invalid device ID", Self::FilterRejected => "event rejected by filter" }
    }
}

pub type InputResult<T> = Result<T, InputError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeymapError { InvalidScanCode, IncompleteExtended, UnknownExtended, PendingDeadKey, InvalidCompose }

impl KeymapError {
    pub const fn as_str(self) -> &'static str {
        match self { Self::InvalidScanCode => "invalid scan code", Self::IncompleteExtended => "incomplete extended scan code", Self::UnknownExtended => "unknown extended scan code", Self::PendingDeadKey => "dead key sequence pending", Self::InvalidCompose => "invalid compose sequence" }
    }
}

pub type KeymapResult<T> = Result<T, KeymapError>;
