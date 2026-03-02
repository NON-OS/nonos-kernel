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
pub enum RunnerError {
    ModuleNotFound,
    AlreadyRunning,
    NotRunning,
    StartupFailed,
    ShutdownFailed,
    StartupTimeout,
    ShutdownTimeout,
    ResourceExhausted,
    InvalidState,
    FaultLimitExceeded,
    WatchdogTimeout,
    MemoryAllocationFailed,
    StackOverflow,
    HeapExhausted,
    EntryPointInvalid,
    SecurityViolation,
}

impl RunnerError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ModuleNotFound => "Module not found",
            Self::AlreadyRunning => "Module already running",
            Self::NotRunning => "Module not running",
            Self::StartupFailed => "Module startup failed",
            Self::ShutdownFailed => "Module shutdown failed",
            Self::StartupTimeout => "Startup timeout exceeded",
            Self::ShutdownTimeout => "Shutdown timeout exceeded",
            Self::ResourceExhausted => "Resource exhausted",
            Self::InvalidState => "Invalid module state",
            Self::FaultLimitExceeded => "Fault retry limit exceeded",
            Self::WatchdogTimeout => "Watchdog timeout",
            Self::MemoryAllocationFailed => "Memory allocation failed",
            Self::StackOverflow => "Stack overflow detected",
            Self::HeapExhausted => "Heap exhausted",
            Self::EntryPointInvalid => "Invalid entry point",
            Self::SecurityViolation => "Security violation",
        }
    }

    pub const fn to_errno(&self) -> i32 {
        match self {
            Self::ModuleNotFound => -2,
            Self::AlreadyRunning => -16,
            Self::NotRunning => -3,
            Self::StartupFailed => -5,
            Self::ShutdownFailed => -5,
            Self::StartupTimeout => -110,
            Self::ShutdownTimeout => -110,
            Self::ResourceExhausted => -12,
            Self::InvalidState => -22,
            Self::FaultLimitExceeded => -11,
            Self::WatchdogTimeout => -110,
            Self::MemoryAllocationFailed => -12,
            Self::StackOverflow => -12,
            Self::HeapExhausted => -12,
            Self::EntryPointInvalid => -8,
            Self::SecurityViolation => -1,
        }
    }
}

pub type RunnerResult<T> = Result<T, RunnerError>;
