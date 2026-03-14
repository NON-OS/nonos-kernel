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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextError {
    NoActiveContext,
    NotInProcessContext,
    CapabilityDenied,
    InvalidProcessId,
    ContextAlreadySet,
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoActiveContext => write!(f, "no active execution context"),
            Self::NotInProcessContext => write!(f, "operation requires process context"),
            Self::CapabilityDenied => write!(f, "capability denied"),
            Self::InvalidProcessId => write!(f, "invalid process id"),
            Self::ContextAlreadySet => write!(f, "context already set for this cpu"),
        }
    }
}
