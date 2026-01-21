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

pub mod rsdp;
pub mod sdt;
pub mod fadt;
pub mod madt;
pub mod hpet;
pub mod mcfg;
pub mod srat;
pub mod slit;

pub use rsdp::*;
pub use sdt::*;
pub use fadt::*;
pub use madt::*;
pub use hpet::*;
pub use mcfg::*;
pub use srat::*;
pub use slit::*;

pub const SIG_RSDT: u32 = u32::from_le_bytes(*b"RSDT");
pub const SIG_XSDT: u32 = u32::from_le_bytes(*b"XSDT");
pub const SIG_FADT: u32 = u32::from_le_bytes(*b"FACP");
pub const SIG_MADT: u32 = u32::from_le_bytes(*b"APIC");
pub const SIG_HPET: u32 = u32::from_le_bytes(*b"HPET");
pub const SIG_MCFG: u32 = u32::from_le_bytes(*b"MCFG");
pub const SIG_SRAT: u32 = u32::from_le_bytes(*b"SRAT");
pub const SIG_SLIT: u32 = u32::from_le_bytes(*b"SLIT");
pub const SIG_DSDT: u32 = u32::from_le_bytes(*b"DSDT");
pub const SIG_SSDT: u32 = u32::from_le_bytes(*b"SSDT");
