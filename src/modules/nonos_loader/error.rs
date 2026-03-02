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
pub enum LoaderError {
    PrivacyPolicyMismatch,
    AttestationFailed,
    NoCapabilities,
    AuthenticationFailed,
    RegistrationFailed,
    LoadFailed,
    SandboxSetupFailed,
    RuntimeStartFailed,
    RuntimeStopFailed,
    UnloadFailed,
}

impl LoaderError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivacyPolicyMismatch => "Privacy policy mismatch",
            Self::AttestationFailed => "Attestation chain not trusted",
            Self::NoCapabilities => "No capabilities present",
            Self::AuthenticationFailed => "Module authentication failed",
            Self::RegistrationFailed => "Failed to register module",
            Self::LoadFailed => "Failed to load module code",
            Self::SandboxSetupFailed => "Failed to set up sandbox",
            Self::RuntimeStartFailed => "Failed to start module runtime",
            Self::RuntimeStopFailed => "Failed to stop module runtime",
            Self::UnloadFailed => "Failed to unload module",
        }
    }
}

pub type LoaderResult<T> = Result<T, LoaderError>;
