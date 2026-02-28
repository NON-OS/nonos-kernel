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
pub enum MultibootError {
    InvalidSize,
    InvalidTag { tag_type: u32 },
    MemoryMapError,
    FramebufferError,
    ModuleError,
    InvalidCmdline,
}

impl MultibootError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidSize => "Invalid multiboot info size",
            Self::InvalidTag { .. } => "Invalid multiboot tag",
            Self::MemoryMapError => "Memory map parsing failed",
            Self::FramebufferError => "Framebuffer info parsing failed",
            Self::ModuleError => "Module info parsing failed",
            Self::InvalidCmdline => "Invalid UTF-8 in command line",
        }
    }
}

impl core::fmt::Display for MultibootError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidTag { tag_type } => {
                write!(f, "Invalid multiboot tag type: {}", tag_type)
            }
            _ => write!(f, "{}", self.as_str()),
        }
    }
}
