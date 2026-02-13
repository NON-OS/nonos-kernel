// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

/// Log severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum LogLevel {
    /// Verbose debugging information
    Trace = 0,
    /// Debugging information
    Debug = 1,
    /// General informational messages
    Info = 2,
    /// Warning conditions
    Warn = 3,
    /// Error conditions
    Error = 4,
    /// Critical conditions requiring immediate attention
    Critical = 5,
    /// System is unusable
    Fatal = 6,
}

impl LogLevel {
    /// Get the string representation for display
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Critical => "CRIT",
            LogLevel::Fatal => "FATAL",
        }
    }

    /// Get short (5-char padded) representation
    pub fn as_str_padded(self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO ",
            LogLevel::Warn => "WARN ",
            LogLevel::Error => "ERROR",
            LogLevel::Critical => "CRIT ",
            LogLevel::Fatal => "FATAL",
        }
    }

    /// Get numeric priority (higher = more severe)
    pub fn priority(self) -> u8 {
        self as u8
    }

    /// Check if this level should be logged given a minimum level
    pub fn should_log(self, min_level: LogLevel) -> bool {
        self.priority() >= min_level.priority()
    }

    /// Create from numeric value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(LogLevel::Trace),
            1 => Some(LogLevel::Debug),
            2 => Some(LogLevel::Info),
            3 => Some(LogLevel::Warn),
            4 => Some(LogLevel::Error),
            5 => Some(LogLevel::Critical),
            6 => Some(LogLevel::Fatal),
            _ => None,
        }
    }
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Info
    }
}

/// Log categories for filtering and organization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogCategory {
    /// Boot sequence messages
    Boot,
    /// Memory management
    Memory,
    /// Graphics/display
    Graphics,
    /// Cryptographic operations
    Crypto,
    /// ZK proof verification
    Zk,
    /// Capsule loading
    Capsule,
    /// Security-related messages
    Security,
    /// Hardware/driver messages
    Hardware,
    /// General system messages
    System,
    /// User-defined category
    Custom,
}

impl LogCategory {
    /// Get string representation
    pub fn as_str(self) -> &'static str {
        match self {
            LogCategory::Boot => "boot",
            LogCategory::Memory => "memory",
            LogCategory::Graphics => "graphics",
            LogCategory::Crypto => "crypto",
            LogCategory::Zk => "zk",
            LogCategory::Capsule => "capsule",
            LogCategory::Security => "security",
            LogCategory::Hardware => "hardware",
            LogCategory::System => "system",
            LogCategory::Custom => "custom",
        }
    }
}
