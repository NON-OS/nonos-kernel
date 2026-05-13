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

// Non-x86 fail-closed for the PIO syscalls. The instruction class
// does not exist on aarch64/riscv64, so every call returns -ENOSYS.
// `-38` is the syscall ABI's `-errno::ENOSYS` encoded as i64. Keep
// this file in sync with `crate::syscall::errnos::ENOSYS`.
const ENOSYS_NEG: i64 = -38;

pub fn sys_pio_grant(_dev: u64, _epoch: u64, _bar: u8, _flags: u32, _out: u64) -> i64 {
    ENOSYS_NEG
}

pub fn sys_pio_read(_grant: u64, _off: u64, _width: u64, _out: u64) -> i64 {
    ENOSYS_NEG
}

pub fn sys_pio_write(_grant: u64, _off: u64, _width: u64, _value: u64) -> i64 {
    ENOSYS_NEG
}

pub fn sys_pio_release(_grant: u64) -> i64 {
    ENOSYS_NEG
}
