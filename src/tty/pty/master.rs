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

use super::pair::get_pair;

pub fn master_read(pty_num: u32, buf: &mut [u8]) -> Result<usize, i32> {
    let pair = get_pair(pty_num).ok_or(-9)?;
    let mut master_buf = pair.master_buf.lock();
    let mut count = 0;
    for byte in buf.iter_mut() {
        if let Some(c) = master_buf.pop() {
            *byte = c;
            count += 1;
        } else {
            break;
        }
    }
    if count == 0 {
        return Err(-11);
    }
    Ok(count)
}

pub fn master_write(pty_num: u32, buf: &[u8]) -> Result<usize, i32> {
    let pair = get_pair(pty_num).ok_or(-9)?;
    let mut slave_buf = pair.slave_buf.lock();
    for &c in buf {
        slave_buf.push(c);
    }
    Ok(buf.len())
}

pub fn master_ioctl(pty_num: u32, cmd: u32, arg: u64) -> Result<i64, i32> {
    let pair = get_pair(pty_num).ok_or(-9)?;
    let mut tty = pair.slave_tty.lock();
    crate::tty::ioctl::tty_ioctl(&mut tty, cmd, arg)
}

pub fn master_poll(pty_num: u32) -> u32 {
    if let Some(pair) = get_pair(pty_num) {
        let master_buf = pair.master_buf.lock();
        let mut events = 0x04;
        if !master_buf.is_empty() {
            events |= 0x01;
        }
        events
    } else {
        0
    }
}
