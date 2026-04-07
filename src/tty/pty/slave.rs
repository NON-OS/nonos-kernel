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

pub fn slave_open(pty_num: u32) -> Result<(), i32> {
    let pair = get_pair(pty_num).ok_or(-6)?;
    if !pair.unlocked.load(core::sync::atomic::Ordering::SeqCst) {
        return Err(-5);
    }
    Ok(())
}

pub fn slave_close(pty_num: u32) -> Result<(), i32> {
    let _ = get_pair(pty_num).ok_or(-9)?;
    Ok(())
}

pub fn slave_read(pty_num: u32, buf: &mut [u8]) -> Result<usize, i32> {
    let pair = get_pair(pty_num).ok_or(-9)?;
    let mut tty = pair.slave_tty.lock();
    let ldisc = tty.ldisc.clone();
    ldisc.read(&mut tty, buf)
}

pub fn slave_write(pty_num: u32, buf: &[u8]) -> Result<usize, i32> {
    let pair = get_pair(pty_num).ok_or(-9)?;
    let mut master_buf = pair.master_buf.lock();
    let tty = pair.slave_tty.lock();
    let mut output = alloc::vec::Vec::new();
    for &c in buf {
        if (tty.termios.c_oflag & crate::tty::termios::OPOST) != 0 {
            if c == b'\n' && (tty.termios.c_oflag & crate::tty::termios::ONLCR) != 0 {
                output.push(b'\r');
            }
        }
        output.push(c);
    }
    for c in output {
        master_buf.push(c);
    }
    Ok(buf.len())
}

pub fn slave_ioctl(pty_num: u32, cmd: u32, arg: u64) -> Result<i64, i32> {
    let pair = get_pair(pty_num).ok_or(-9)?;
    let mut tty = pair.slave_tty.lock();
    crate::tty::ioctl::tty_ioctl(&mut tty, cmd, arg)
}

pub fn slave_poll(pty_num: u32) -> u32 {
    if let Some(pair) = get_pair(pty_num) {
        let slave_buf = pair.slave_buf.lock();
        let mut events = 0x04;
        if !slave_buf.is_empty() {
            events |= 0x01;
        }
        events
    } else {
        0
    }
}
