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
#[repr(u8)]
pub enum SanitizationLevel {
    None = 0,
    Basic = 1,
    Standard = 2,
    Paranoid = 3,
    Gutmann = 4,
}

impl Default for SanitizationLevel {
    fn default() -> Self {
        SanitizationLevel::Standard
    }
}

impl SanitizationLevel {
    pub fn from_u64(val: u64) -> Self {
        match val {
            0 => SanitizationLevel::None,
            1 => SanitizationLevel::Basic,
            2 => SanitizationLevel::Standard,
            3 => SanitizationLevel::Paranoid,
            4 => SanitizationLevel::Gutmann,
            _ => SanitizationLevel::Standard,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StackCanaryConfig {
    pub enabled: bool,
    pub canary_value: u64,
    pub check_frequency: u32,
}

impl Default for StackCanaryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            canary_value: 0xDEAD_BEEF_CAFE_BABE,
            check_frequency: 1,
        }
    }
}

impl StackCanaryConfig {
    /// Check if canary protection is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get canary value
    pub fn get_canary(&self) -> u64 {
        self.canary_value
    }

    /// Get check frequency
    pub fn get_frequency(&self) -> u32 {
        self.check_frequency
    }

    /// Verify canary value
    pub fn verify(&self, value: u64) -> bool {
        !self.enabled || value == self.canary_value
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SanitizationStats {
    pub bytes_sanitized: usize,
    pub sanitization_calls: usize,
    pub level: SanitizationLevel,
    pub canary_enabled: bool,
}

impl SanitizationStats {
    /// Get total bytes sanitized
    pub fn get_bytes_sanitized(&self) -> usize {
        self.bytes_sanitized
    }

    /// Get number of sanitization calls
    pub fn get_call_count(&self) -> usize {
        self.sanitization_calls
    }

    /// Get current sanitization level
    pub fn get_level(&self) -> SanitizationLevel {
        self.level
    }

    /// Check if canary protection is enabled
    pub fn is_canary_enabled(&self) -> bool {
        self.canary_enabled
    }

    /// Get average bytes per call
    pub fn avg_bytes_per_call(&self) -> usize {
        if self.sanitization_calls == 0 {
            0
        } else {
            self.bytes_sanitized / self.sanitization_calls
        }
    }
}
