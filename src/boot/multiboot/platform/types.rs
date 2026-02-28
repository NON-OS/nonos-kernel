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
pub enum Platform {
    Qemu,
    VirtualMachine,
    BareMetal,
}

impl Platform {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Qemu => "QEMU",
            Self::VirtualMachine => "Virtual Machine",
            Self::BareMetal => "Bare Metal",
        }
    }

    #[inline]
    pub fn is_virtual(&self) -> bool {
        !matches!(self, Self::BareMetal)
    }

    pub fn optimize_for_platform(&self) {
        match self {
            Self::Qemu => {
                crate::log::info!("Detected QEMU - applying virtualization optimizations");
            }
            Self::VirtualMachine => {
                crate::log::info!("Detected virtual machine - applying general VM optimizations");
            }
            Self::BareMetal => {
                crate::log::info!("Detected bare-metal hardware - applying hardware optimizations");
            }
        }
    }

    #[inline]
    pub fn timer_frequency(&self) -> u32 {
        match self {
            Self::Qemu => 1000,
            Self::VirtualMachine => 100,
            Self::BareMetal => 1000,
        }
    }

    #[inline]
    pub fn supports_virtio(&self) -> bool {
        matches!(self, Self::Qemu | Self::VirtualMachine)
    }

    #[inline]
    pub fn console_type(&self) -> ConsoleType {
        match self {
            Self::Qemu => ConsoleType::Serial,
            Self::VirtualMachine | Self::BareMetal => ConsoleType::Vga,
        }
    }
}

impl core::fmt::Display for Platform {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleType {
    Vga,
    Serial,
    Framebuffer,
}

impl ConsoleType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Vga => "VGA",
            Self::Serial => "Serial",
            Self::Framebuffer => "Framebuffer",
        }
    }
}

impl core::fmt::Display for ConsoleType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
