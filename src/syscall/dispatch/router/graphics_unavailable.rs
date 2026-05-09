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

//! Graphics numbers park here and return ENOTSUP until a backend lands.

use crate::syscall::numbers::SyscallNumber;
use crate::syscall::SyscallResult;

const ENOTSUP: i32 = 95;

pub(super) fn matches(nr: SyscallNumber) -> bool {
    matches!(
        nr,
        SyscallNumber::GraphicsDisplayDimensions
            | SyscallNumber::GraphicsSurfaceCreate
            | SyscallNumber::GraphicsSurfaceDestroy
            | SyscallNumber::GraphicsSurfaceMap
            | SyscallNumber::GraphicsSurfacePresentFull
            | SyscallNumber::GraphicsSurfacePresentRect
            | SyscallNumber::GraphicsDisplayList
            | SyscallNumber::GraphicsCursorPresent
    )
}

pub(super) fn handle() -> SyscallResult {
    super::super::util::errno(ENOTSUP)
}
