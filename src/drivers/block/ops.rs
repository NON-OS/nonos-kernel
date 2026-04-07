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

use super::registry::get_device;

pub fn open(_name: &str) -> Result<(), i32> {
    Ok(())
}

pub fn close(_name: &str) -> Result<(), i32> {
    Ok(())
}

pub fn read(name: &str, buf: &mut [u8], offset: u64) -> Result<usize, i32> {
    let dev = get_device(name).ok_or(-19i32)?;
    dev.read(buf, offset)
}

pub fn write(name: &str, buf: &[u8], offset: u64) -> Result<usize, i32> {
    let dev = get_device(name).ok_or(-19i32)?;
    dev.write(buf, offset)
}

pub fn flush(name: &str) -> Result<(), i32> {
    let dev = get_device(name).ok_or(-19i32)?;
    dev.flush()
}

pub fn ioctl(name: &str, cmd: u32, arg: u64) -> Result<i64, i32> {
    let dev = get_device(name).ok_or(-19i32)?;
    dev.ioctl(cmd, arg)
}
