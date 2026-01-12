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
    ImageTooSmall,
    ImageTooLarge,
    InvalidName,
    EmptyName,
    InvalidSignature,
    EmptyCode,
    AuthenticationFailed,
    PrivacyPolicyMismatch,
    AttestationFailed,
    RegistrationFailed,
    SandboxSetupFailed,
    StartFailed,
    ModuleNotFound,
    StopFailed,
}

impl LoaderError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ImageTooSmall => "Module image too small",
            Self::ImageTooLarge => "Module image too large",
            Self::InvalidName => "Invalid module name",
            Self::EmptyName => "Empty module name",
            Self::InvalidSignature => "Invalid signature",
            Self::EmptyCode => "Empty module code",
            Self::AuthenticationFailed => "Authentication failed",
            Self::PrivacyPolicyMismatch => "Privacy policy mismatch",
            Self::AttestationFailed => "Attestation failed",
            Self::RegistrationFailed => "Registration failed",
            Self::SandboxSetupFailed => "Sandbox setup failed",
            Self::StartFailed => "Module start failed",
            Self::ModuleNotFound => "Module not found",
            Self::StopFailed => "Module stop failed",
        }
    }

    pub const fn to_errno(&self) -> i32 {
        match self {
            Self::ImageTooSmall => -22,
            Self::ImageTooLarge => -7,
            Self::InvalidName => -22,
            Self::EmptyName => -22,
            Self::InvalidSignature => -22,
            Self::EmptyCode => -22,
            Self::AuthenticationFailed => -1,
            Self::PrivacyPolicyMismatch => -1,
            Self::AttestationFailed => -1,
            Self::RegistrationFailed => -12,
            Self::SandboxSetupFailed => -12,
            Self::StartFailed => -5,
            Self::ModuleNotFound => -2,
            Self::StopFailed => -5,
        }
    }
}

impl core::fmt::Display for LoaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type LoaderResult<T> = Result<T, LoaderError>;
