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

pub use super::error_types::BootError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_messages() {
        assert_eq!(BootError::None.as_str(), "no error");
        assert_eq!(BootError::NoSse.as_str(), "SSE not supported (required for x86_64)");
    }

    #[test]
    fn test_error_from_u8() {
        assert_eq!(BootError::from_u8(0), BootError::None);
        assert_eq!(BootError::from_u8(6), BootError::NoSse);
        assert_eq!(BootError::from_u8(255), BootError::Unknown);
    }

    #[test]
    fn test_is_fatal() {
        assert!(!BootError::None.is_fatal());
        assert!(BootError::NoSse.is_fatal());
    }

    #[test]
    fn test_is_cpu_related() {
        assert!(BootError::NoCpuid.is_cpu_related());
        assert!(!BootError::InvalidPageTable.is_cpu_related());
    }

    #[test]
    fn test_is_memory_related() {
        assert!(BootError::InvalidPageTable.is_memory_related());
        assert!(!BootError::NoSse.is_memory_related());
    }
}
