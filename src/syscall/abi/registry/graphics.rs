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

// Graphics family. Routed through the in-kernel graphics router
// (`syscall::dispatch::router::graphics_present` /
// `graphics_backend`) until a graphics capsule takes over; the ABI
// is preserved so that capsule binaries can be re-linked unchanged.
pub(super) const ENTRIES: &[AbiEntry] = &[
    r(b"GDIM", SyscallNumber::GraphicsDisplayDimensions, "GraphicsDisplayDimensions"),
    r(b"GSCR", SyscallNumber::GraphicsSurfaceCreate, "GraphicsSurfaceCreate"),
    r(b"GSDS", SyscallNumber::GraphicsSurfaceDestroy, "GraphicsSurfaceDestroy"),
    r(b"GSMP", SyscallNumber::GraphicsSurfaceMap, "GraphicsSurfaceMap"),
    r(b"GPRF", SyscallNumber::GraphicsSurfacePresentFull, "GraphicsSurfacePresentFull"),
    r(b"GPRR", SyscallNumber::GraphicsSurfacePresentRect, "GraphicsSurfacePresentRect"),
    r(b"GDLS", SyscallNumber::GraphicsDisplayList, "GraphicsDisplayList"),
    r(b"GCUR", SyscallNumber::GraphicsCursorPresent, "GraphicsCursorPresent"),
];

const fn r(tag: &[u8; 4], variant: SyscallNumber, name: &'static str) -> AbiEntry {
    AbiEntry {
        id: tag4(tag),
        variant,
        name,
        domain: AbiDomain::Graphics,
        status: AbiStatus::Routed,
    }
}
