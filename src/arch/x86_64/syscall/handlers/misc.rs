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

use crate::usercopy::{validate_user_write, copy_to_user};
use super::uname_types::Utsname;

const EFAULT: i64 = -14;

pub fn syscall_uname(buf: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    if buf == 0 {
        return EFAULT as u64;
    }
    if validate_user_write(buf, Utsname::SIZE).is_err() {
        return EFAULT as u64;
    }
    let utsname = Utsname::new();
    if copy_to_user(buf, utsname.as_bytes()).is_err() {
        return EFAULT as u64;
    }
    0
}
