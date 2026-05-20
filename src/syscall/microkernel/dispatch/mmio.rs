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

use super::args::Args;
use crate::syscall::microkernel::mmio::sys_mmio_unmap;
use crate::syscall::microkernel::numbers::*;

pub(super) fn handle(nr: u64, a: Args) -> Option<i64> {
    Some(match nr {
        SYS_MMIO_MAP => super::unpack::mmio_map(a.a0, a.a1, a.a2, a.a3, a.a4, a.a5),
        SYS_MMIO_UNMAP => sys_mmio_unmap(a.a0),
        _ => return None,
    })
}
