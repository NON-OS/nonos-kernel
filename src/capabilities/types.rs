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
    RegisterService,
    GraphicsDisplayQuery,
    GraphicsSurfaceCreate,
}

impl Capability {
    #[inline]
    pub(crate) const fn bit(self) -> u64 {
        match self {
            Self::CoreExec => 1,
            Self::IO => 2,
            Self::Network => 4,
            Self::IPC => 8,
            Self::Memory => 16,
            Self::Crypto => 32,
            Self::FileSystem => 64,
            Self::Hardware => 128,
            Self::Debug => 256,
            Self::Admin => 512,
            Self::RegisterService => 1024,
            Self::GraphicsDisplayQuery => 2048,
            Self::GraphicsSurfaceCreate => 4096,
        }
    }

    pub const fn all() -> [Capability; 13] {
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
            Self::RegisterService,
            Self::GraphicsDisplayQuery,
            Self::GraphicsSurfaceCreate,
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
            Self::RegisterService => "RegisterService",
            Self::GraphicsDisplayQuery => "GraphicsDisplayQuery",
            Self::GraphicsSurfaceCreate => "GraphicsSurfaceCreate",
        }
    }

    pub const fn count() -> usize {
        13
    }
}

impl core::fmt::Display for Capability {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
