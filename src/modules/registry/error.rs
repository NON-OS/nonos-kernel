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
pub enum RegistryError {
    ModuleNotFound,
    ModuleAlreadyExists,
    RegistryFull,
    InvalidState,
    ModuleRunning,
}

impl RegistryError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ModuleNotFound => "Module not found",
            Self::ModuleAlreadyExists => "Module already exists",
            Self::RegistryFull => "Registry full",
            Self::InvalidState => "Invalid module state",
            Self::ModuleRunning => "Module is running",
        }
    }

    pub const fn to_errno(&self) -> i32 {
        match self {
            Self::ModuleNotFound => -2,
            Self::ModuleAlreadyExists => -17,
            Self::RegistryFull => -12,
            Self::InvalidState => -22,
            Self::ModuleRunning => -16,
        }
    }
}

pub type RegistryResult<T> = Result<T, RegistryError>;
