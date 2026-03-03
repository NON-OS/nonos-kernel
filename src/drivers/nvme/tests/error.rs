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

extern crate alloc;

#[cfg(test)]
mod tests {
    use crate::drivers::nvme::error;

    #[test]
    fn test_error_display() {
        let err = error::NvmeError::NoControllerFound;
        assert_eq!(err.as_str(), "No NVMe controller found on PCI bus");

        let err = error::NvmeError::CommandFailed { status_code: 0x281 };
        let s = alloc::format!("{}", err);
        assert!(s.contains("0x281"));
    }

    #[test]
    fn test_error_classification() {
        assert!(error::NvmeError::ControllerFatalStatus.is_fatal());
        assert!(error::NvmeError::CqCorruption.is_fatal());
        assert!(!error::NvmeError::CommandTimeout.is_fatal());

        assert!(error::NvmeError::CommandTimeout.is_recoverable());
        assert!(error::NvmeError::RateLimitExceeded.is_recoverable());
        assert!(!error::NvmeError::ControllerFatalStatus.is_recoverable());
    }

    #[test]
    fn test_status_code_parsing() {
        let status = error::NvmeStatusCode::from_status_field(0x0000);
        assert!(status.is_success());

        let status = error::NvmeStatusCode::from_status_field(0x0002);
        assert_eq!(status, error::NvmeStatusCode::InvalidOpcode);

        let status = error::NvmeStatusCode::from_status_field(0x0004);
        assert_eq!(status, error::NvmeStatusCode::InvalidField);
    }
}
