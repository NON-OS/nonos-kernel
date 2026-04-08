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
pub enum CpuVendor {
    Intel,
    Amd,
    Unknown,
}

impl CpuVendor {
    pub fn detect() -> Self {
        let result = core::arch::x86_64::__cpuid(0);
        let vendor_bytes: [u8; 12] = unsafe {
            core::mem::transmute([result.ebx, result.edx, result.ecx])
        };

        match &vendor_bytes {
            b"GenuineIntel" => Self::Intel,
            b"AuthenticAMD" => Self::Amd,
            _ => Self::Unknown,
        }
    }

    pub const fn name(&self) -> &'static str {
        match self {
            Self::Intel => "Intel",
            Self::Amd => "AMD",
            Self::Unknown => "Unknown",
        }
    }
}
