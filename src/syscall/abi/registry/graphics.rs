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

use crate::syscall::abi::{tag4, AbiDomain, AbiEntry, AbiStatus};
use crate::syscall::numbers::SyscallNumber;

// Graphics family. Reserved Unavailable; dispatcher routes all to
// `graphics_unavailable::handle` which returns ENOTSUP. A future
// graphics capsule will register handlers; the ABI is preserved so
// that capsule binaries can be re-linked unchanged.
pub(super) const ENTRIES: &[AbiEntry] = &[
    u(b"GDIM", SyscallNumber::GraphicsDisplayDimensions, "GraphicsDisplayDimensions"),
    u(b"GSCR", SyscallNumber::GraphicsSurfaceCreate, "GraphicsSurfaceCreate"),
    u(b"GSDS", SyscallNumber::GraphicsSurfaceDestroy, "GraphicsSurfaceDestroy"),
    u(b"GSMP", SyscallNumber::GraphicsSurfaceMap, "GraphicsSurfaceMap"),
    u(b"GPRF", SyscallNumber::GraphicsSurfacePresentFull, "GraphicsSurfacePresentFull"),
    u(b"GPRR", SyscallNumber::GraphicsSurfacePresentRect, "GraphicsSurfacePresentRect"),
    u(b"GDLS", SyscallNumber::GraphicsDisplayList, "GraphicsDisplayList"),
    u(b"GCUR", SyscallNumber::GraphicsCursorPresent, "GraphicsCursorPresent"),
];

const fn u(tag: &[u8; 4], variant: SyscallNumber, name: &'static str) -> AbiEntry {
    AbiEntry {
        id: tag4(tag),
        variant,
        name,
        domain: AbiDomain::Graphics,
        status: AbiStatus::Unavailable,
    }
}
