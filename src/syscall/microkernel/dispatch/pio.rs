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
use crate::syscall::microkernel::numbers::*;
use crate::syscall::microkernel::pio::{
    sys_pio_grant, sys_pio_read, sys_pio_release, sys_pio_write,
};

pub(super) fn handle(nr: u64, a: Args) -> Option<i64> {
    Some(match nr {
        SYS_PIO_GRANT => sys_pio_grant(a.a0, a.a1, a.a2 as u8, a.a3 as u32, a.a4),
        SYS_PIO_READ => sys_pio_read(a.a0, a.a1, a.a2, a.a3),
        SYS_PIO_WRITE => sys_pio_write(a.a0, a.a1, a.a2, a.a3),
        SYS_PIO_RELEASE => sys_pio_release(a.a0),
        _ => return None,
    })
}
