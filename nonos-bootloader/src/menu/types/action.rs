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

use super::mode::SecurityMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuAction {
    Boot(SecurityMode),
    Recovery,
    Diagnostics,
    SecurityStatus,
    Continue,
    Timeout,
    Shutdown,
}

impl MenuAction {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Boot(SecurityMode::Development) => "Boot (Development Mode)",
            Self::Boot(SecurityMode::Standard) => "Boot (Standard Mode)",
            Self::Boot(SecurityMode::Hardened) => "Boot (Hardened Mode)",
            Self::Recovery => "Recovery Mode",
            Self::Diagnostics => "Hardware Diagnostics",
            Self::SecurityStatus => "Security Status",
            Self::Continue => "Continue Boot",
            Self::Timeout => "Boot (Default)",
            Self::Shutdown => "Shutdown",
        }
    }

    pub const fn requires_verification(&self) -> bool {
        match self {
            Self::Boot(SecurityMode::Standard) => true,
            Self::Boot(SecurityMode::Hardened) => true,
            _ => false,
        }
    }
}
