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
pub enum LifecycleState {
    Stopped = 0,
    Starting = 1,
    Running = 2,
    Suspended = 3,
    Stopping = 4,
    Failed = 5,
}

impl LifecycleState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "Stopped",
            Self::Starting => "Starting",
            Self::Running => "Running",
            Self::Suspended => "Suspended",
            Self::Stopping => "Stopping",
            Self::Failed => "Failed",
        }
    }

    pub const fn is_active(self) -> bool {
        matches!(self, Self::Running | Self::Suspended)
    }

    pub const fn can_start(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed)
    }

    pub const fn can_stop(self) -> bool {
        matches!(self, Self::Running | Self::Suspended)
    }

    pub const fn can_suspend(self) -> bool {
        matches!(self, Self::Running)
    }

    pub const fn can_resume(self) -> bool {
        matches!(self, Self::Suspended)
    }
}

impl Default for LifecycleState {
    fn default() -> Self {
        Self::Stopped
    }
}

impl core::fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
