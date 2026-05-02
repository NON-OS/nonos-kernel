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

use super::cause::TrapCause;

/// Portable view of a captured trap frame. The per-arch shim implements
/// this on its concrete frame; the contract goes through these methods
/// only.
///
/// Only x86 projects a real frame here today. Other arches add their
/// own projection when their trap shims land.
pub trait TrapFrame {
    fn instruction_pointer(&self) -> u64;
    fn stack_pointer(&self) -> u64;
    fn from_user(&self) -> bool;

    /// Cause projection runs here. Arch-specific status reads (CR2,
    /// ESR_EL1, scause / stval) happen in the impl, not in the contract.
    fn cause(&self) -> TrapCause;
}
