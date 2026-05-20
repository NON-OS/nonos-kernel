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
use crate::syscall::microkernel::device::{sys_device_claim, sys_device_list, sys_device_release};
use crate::syscall::microkernel::numbers::*;

pub(super) fn handle(nr: u64, a: Args) -> Option<i64> {
    Some(match nr {
        SYS_DEVICE_LIST => sys_device_list(a.a0 as u32, a.a1, a.a2),
        SYS_DEVICE_CLAIM => sys_device_claim(a.a0),
        SYS_DEVICE_RELEASE => sys_device_release(a.a0),
        _ => return None,
    })
}
