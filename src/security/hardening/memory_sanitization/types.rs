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

#[derive(Debug, Clone, Copy)]
pub struct SanitizationStats {
    pub bytes_sanitized: usize,
    pub sanitization_calls: usize,
    pub level: SanitizationLevel,
    pub canary_enabled: bool,
}
