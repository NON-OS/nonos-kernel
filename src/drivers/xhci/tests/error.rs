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

#[cfg(test)]
mod tests {
    use crate::drivers::xhci::XhciError;

    #[test]
    fn test_error_display() {
        let err = XhciError::InvalidSlotId(5);
        assert_eq!(err.as_str(), "Invalid slot ID");

        let err = XhciError::Timeout;
        assert_eq!(err.as_str(), "Operation timeout");
    }

    #[test]
    fn test_completion_code_extraction() {
        let err = XhciError::CompletionCodeError(6);
        assert_eq!(err.completion_code(), Some(6));

        let err = XhciError::Timeout;
        assert_eq!(err.completion_code(), None);
    }

    #[test]
    fn test_error_requires_reset() {
        assert!(XhciError::Stall.requires_endpoint_reset());
        assert!(XhciError::BabbleDetected.requires_endpoint_reset());
        assert!(!XhciError::Timeout.requires_endpoint_reset());
    }

    #[test]
    fn test_error_is_recoverable() {
        assert!(XhciError::Timeout.is_recoverable());
        assert!(XhciError::Stall.is_recoverable());
        assert!(!XhciError::HostSystemError.is_fatal());
    }

    #[test]
    fn test_from_completion_code() {
        assert!(XhciError::from_completion_code(1).is_none());
        assert!(matches!(
            XhciError::from_completion_code(6),
            Some(XhciError::Stall)
        ));
        assert!(matches!(
            XhciError::from_completion_code(3),
            Some(XhciError::BabbleDetected)
        ));
    }
}
