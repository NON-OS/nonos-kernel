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


use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmError {
    NotInitialized,
    NotPresent,
    Timeout,
    InvalidResponse,
    LocalityError,
    CommandFailed(u32),
    BufferTooSmall,
    InvalidParameter,
    AuthFailed,
    NvError,
    PcrError,
    CommunicationError,
    HardwareError,
    RateLimitExceeded,
}

impl TpmError {
    pub fn as_str(&self) -> &'static str {
        match self {
            TpmError::NotInitialized => "TPM not initialized",
            TpmError::NotPresent => "TPM not present",
            TpmError::Timeout => "TPM operation timed out",
            TpmError::InvalidResponse => "invalid TPM response",
            TpmError::LocalityError => "locality access error",
            TpmError::CommandFailed(_) => "TPM command failed",
            TpmError::BufferTooSmall => "buffer too small",
            TpmError::InvalidParameter => "invalid parameter",
            TpmError::AuthFailed => "authentication failed",
            TpmError::NvError => "NV storage error",
            TpmError::PcrError => "PCR operation error",
            TpmError::CommunicationError => "communication error",
            TpmError::HardwareError => "hardware error",
            TpmError::RateLimitExceeded => "rate limit exceeded",
        }
    }

    pub fn response_code(&self) -> Option<u32> {
        match self {
            TpmError::CommandFailed(rc) => Some(*rc),
            _ => None,
        }
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            TpmError::Timeout
                | TpmError::LocalityError
                | TpmError::BufferTooSmall
                | TpmError::InvalidParameter
                | TpmError::RateLimitExceeded
        )
    }

    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            TpmError::NotPresent | TpmError::HardwareError
        )
    }
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TpmError::CommandFailed(rc) => {
                write!(f, "TPM command failed with code 0x{:08x}", rc)
            }
            _ => write!(f, "{}", self.as_str()),
        }
    }
}

pub type TpmResult<T> = Result<T, TpmError>;

pub(super) fn _parse_response_code(rc: u32) -> _ResponseCodeInfo {
    let format_2 = (rc & 0x80) != 0;
    let severity = if format_2 { (rc & 0x40) != 0 } else { true };
    let error_num = (rc & 0x3F) as u8;
    let param_num = ((rc >> 8) & 0x0F) as u8;

    _ResponseCodeInfo {
        raw: rc,
        is_error: rc != 0,
        is_tpm2_format: format_2,
        is_fatal: severity,
        error_number: error_num,
        parameter_number: param_num,
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct _ResponseCodeInfo {
    pub raw: u32,
    pub is_error: bool,
    pub is_tpm2_format: bool,
    pub is_fatal: bool,
    pub error_number: u8,
    pub parameter_number: u8,
}

pub(super) mod response_codes {
    pub(crate) const TPM_RC_INITIALIZE: u32 = 0x100;
}

#[cfg(all(test, not(feature = "std")))]
mod tests {
    use super::*;

    #[test]
    fn test_error_as_str() {
        assert_eq!(TpmError::NotPresent.as_str(), "TPM not present");
        assert_eq!(TpmError::Timeout.as_str(), "TPM operation timed out");
    }

    #[test]
    fn test_response_code() {
        let err = TpmError::CommandFailed(0x123);
        assert_eq!(err.response_code(), Some(0x123));
        assert_eq!(TpmError::Timeout.response_code(), None);
    }

    #[test]
    fn test_parse_response_code() {
        let info = parse_response_code(0);
        assert!(!info.is_error);

        let info = parse_response_code(0x100);
        assert!(info.is_error);
    }
}
