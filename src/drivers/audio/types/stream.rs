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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StreamState {
    Stopped = 0,
    Running = 1,
    Paused = 2,
    Error = 3,
    Resetting = 4,
    Ready = 5,
}

impl StreamState {
    #[inline]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Running)
    }

    #[inline]
    pub const fn can_start(&self) -> bool {
        matches!(self, Self::Stopped | Self::Ready | Self::Paused)
    }

    #[inline]
    pub const fn can_stop(&self) -> bool {
        matches!(self, Self::Running | Self::Paused | Self::Error)
    }

    #[inline]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::Error)
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Error => "error",
            Self::Resetting => "resetting",
            Self::Ready => "ready",
        }
    }
}

impl Default for StreamState {
    fn default() -> Self {
        Self::Stopped
    }
}

impl fmt::Display for StreamState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
