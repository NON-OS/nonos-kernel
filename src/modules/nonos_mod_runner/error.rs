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
pub enum RunnerError {
    AttestationFailed,
    CapabilityViolation,
    SandboxSetupFailed,
    StartFailed,
    StopFailed,
    SandboxDestroyFailed,
    ModuleInfoFailed,
    SecureEraseFailed,
    InvalidState,
    NotFound,
}

impl RunnerError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AttestationFailed => "Runtime attestation failed",
            Self::CapabilityViolation => "Capability boundary violation",
            Self::SandboxSetupFailed => "Failed to set up sandbox",
            Self::StartFailed => "Failed to start module",
            Self::StopFailed => "Failed to stop module",
            Self::SandboxDestroyFailed => "Failed to destroy sandbox",
            Self::ModuleInfoFailed => "Failed to get module info",
            Self::SecureEraseFailed => "Failed to securely erase module memory",
            Self::InvalidState => "Module is not in expected state",
            Self::NotFound => "Module not found",
        }
    }
}

pub type RunnerResult<T> = Result<T, RunnerError>;
