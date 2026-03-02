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
pub enum ModuleLoaderError {
    NotFound,
    InvalidSignature,
    AttestationFailed,
    HashMismatch,
    InvalidState,
    NotRunning,
    CryptoInitFailed,
    MemoryProtectionFailed,
}

impl ModuleLoaderError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotFound => "Module not found",
            Self::InvalidSignature => "Invalid module signature",
            Self::AttestationFailed => "Module attestation verification failed",
            Self::HashMismatch => "Module hash verification failed",
            Self::InvalidState => "Module not in loadable state",
            Self::NotRunning => "Module not running",
            Self::CryptoInitFailed => "Crypto subsystem initialization failed",
            Self::MemoryProtectionFailed => "Memory protection initialization failed",
        }
    }
}

impl core::fmt::Display for ModuleLoaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type ModuleLoaderResult<T> = Result<T, ModuleLoaderError>;
