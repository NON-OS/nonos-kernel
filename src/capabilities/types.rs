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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    CoreExec,
    IO,
    Network,
    IPC,
    Memory,
    Crypto,
    FileSystem,
    Hardware,
    Debug,
    Admin,
}

impl Capability {
    #[inline]
    pub(crate) const fn bit(self) -> u64 {
        match self {
            Self::CoreExec => 1 << 0,
            Self::IO => 1 << 1,
            Self::Network => 1 << 2,
            Self::IPC => 1 << 3,
            Self::Memory => 1 << 4,
            Self::Crypto => 1 << 5,
            Self::FileSystem => 1 << 6,
            Self::Hardware => 1 << 7,
            Self::Debug => 1 << 8,
            Self::Admin => 1 << 9,
        }
    }

    pub const fn all() -> [Capability; 10] {
        [
            Self::CoreExec,
            Self::IO,
            Self::Network,
            Self::IPC,
            Self::Memory,
            Self::Crypto,
            Self::FileSystem,
            Self::Hardware,
            Self::Debug,
            Self::Admin,
        ]
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::CoreExec => "CoreExec",
            Self::IO => "IO",
            Self::Network => "Network",
            Self::IPC => "IPC",
            Self::Memory => "Memory",
            Self::Crypto => "Crypto",
            Self::FileSystem => "FileSystem",
            Self::Hardware => "Hardware",
            Self::Debug => "Debug",
            Self::Admin => "Admin",
        }
    }

    pub const fn count() -> usize {
        10
    }
}

impl core::fmt::Display for Capability {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
