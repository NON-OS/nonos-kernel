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

mod cr;
mod msr;
mod pci;
mod smram;

pub use cr::{read_cr4, write_cr4};
pub use msr::{read_msr, write_msr};
pub use pci::{get_acpi_pm_base, read_pci_byte, read_pci_dword, write_pci_byte};
pub use smram::read_smram;
