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
pub enum EntropyError {
    NoHardwareSource,
    HardwareFailure,
    InsufficientEntropy,
    NotInitialized,
}

impl EntropyError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoHardwareSource => "No hardware entropy source available",
            Self::HardwareFailure => "Hardware entropy source failed after retries",
            Self::InsufficientEntropy => "Insufficient entropy collected",
            Self::NotInitialized => "Entropy system not initialized",
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;

    #[test]
    fn test_error_as_str() {
        assert_eq!(EntropyError::NoHardwareSource.as_str(), "No hardware entropy source available");
        assert_eq!(EntropyError::HardwareFailure.as_str(), "Hardware entropy source failed after retries");
        assert_eq!(EntropyError::InsufficientEntropy.as_str(), "Insufficient entropy collected");
        assert_eq!(EntropyError::NotInitialized.as_str(), "Entropy system not initialized");
    }

    #[test]
    fn test_error_variants_are_distinct() {
        let variants = [
            EntropyError::NoHardwareSource,
            EntropyError::HardwareFailure,
            EntropyError::InsufficientEntropy,
            EntropyError::NotInitialized,
        ];
        for (i, a) in variants.iter().enumerate() {
            for b in &variants[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn test_error_clone_eq() {
        let err = EntropyError::HardwareFailure;
        let cloned = err;
        assert_eq!(err, cloned);
    }

    #[test]
    fn test_error_debug() {
        let err = EntropyError::NoHardwareSource;
        let dbg = alloc::format!("{:?}", err);
        assert!(dbg.contains("NoHardwareSource"));
    }
}
