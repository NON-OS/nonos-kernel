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

// Invariant: returned `KernelHandoff` borrows from `handoff` for its
// arch-specific tail; lifetime is bounded by the source handoff.

use super::super::arch::ArchSpecificHandoff;
use super::super::console::EarlyConsole;
use super::super::handoff::KernelHandoff;
use super::builders;
use crate::boot::handoff::BootHandoffV1;

const X86_LEGACY_SERIAL_PORT: u16 = 0x3F8;

impl<'a> KernelHandoff<'a> {
    pub fn from_x86_64(handoff: &'a BootHandoffV1) -> Self {
        Self {
            memory: builders::memory(handoff),
            cpus: builders::cpus(handoff),
            console: EarlyConsole::LegacySerial(X86_LEGACY_SERIAL_PORT),
            framebuffer: builders::framebuffer(handoff),
            timing: builders::timing(handoff),
            measurement: builders::measurement(handoff),
            arch: ArchSpecificHandoff::X86_64 { v1: handoff },
        }
    }
}
