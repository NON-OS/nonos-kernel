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

// Per-architecture handoff payload.
//
// Kernel-core code does not match on this enum. Code that needs
// arch-specific information (EFI memory descriptor walk, UEFI
// framebuffer init, ACPI table pointer, DTB pointer, GIC/PLIC base
// addresses) downcasts to the active variant.
//
// The enum has one variant per supported architecture. Today only
// x86_64 has a tracked, compiling boot path. aarch64 and riscv64
// variants are added when their boot trees land on `main` with
// matching `from_aarch64` / `from_riscv64` constructors.

use super::super::types::handoff::BootHandoffV1;

#[derive(Debug, Clone, Copy)]
pub enum ArchSpecificHandoff<'a> {
    X86_64 { v1: &'a BootHandoffV1 },
}
