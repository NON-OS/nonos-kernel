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

extern crate alloc;

use super::driver::TtyStruct;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use spin::Mutex;

static TTYS: Mutex<BTreeMap<u32, Arc<Mutex<TtyStruct>>>> = Mutex::new(BTreeMap::new());

pub trait TtyOps: Send + Sync {
    fn read(&self, tty: &mut TtyStruct, buf: &mut [u8]) -> Result<usize, i32>;
    fn write(&self, tty: &mut TtyStruct, buf: &[u8]) -> Result<usize, i32>;
    fn ioctl(&self, tty: &mut TtyStruct, cmd: u32, arg: u64) -> Result<i64, i32>;
    fn poll(&self, tty: &TtyStruct) -> u32;
}

pub fn read(minor: u32, buf: &mut [u8]) -> Result<usize, i32> {
    let ttys = TTYS.lock();
    let tty = ttys.get(&minor).ok_or(-6)?;
    let mut tty_guard = tty.lock();
    let ldisc = tty_guard.ldisc.clone();
    ldisc.read(&mut tty_guard, buf)
}

pub fn write(minor: u32, buf: &[u8]) -> Result<usize, i32> {
    let ttys = TTYS.lock();
    let tty = ttys.get(&minor).ok_or(-6)?;
    let mut tty_guard = tty.lock();
    let ldisc = tty_guard.ldisc.clone();
    ldisc.write(&mut tty_guard, buf)
}

pub fn ioctl(minor: u32, cmd: u32, arg: u64) -> Result<i64, i32> {
    let ttys = TTYS.lock();
    let tty = ttys.get(&minor).ok_or(-6)?;
    let mut tty_guard = tty.lock();
    super::ioctl::tty_ioctl(&mut tty_guard, cmd, arg)
}

pub fn poll(minor: u32) -> u32 {
    let ttys = TTYS.lock();
    if let Some(tty) = ttys.get(&minor) {
        let tty_guard = tty.lock();
        tty_guard.ldisc.poll(&tty_guard)
    } else {
        0
    }
}

pub fn register_tty(minor: u32, tty: Arc<Mutex<TtyStruct>>) {
    TTYS.lock().insert(minor, tty);
}

pub fn unregister_tty(minor: u32) {
    TTYS.lock().remove(&minor);
}

pub fn get_tty(minor: u32) -> Option<Arc<Mutex<TtyStruct>>> {
    TTYS.lock().get(&minor).cloned()
}

pub fn set_termios(fd: i32, termios: &[u8]) -> Result<(), &'static str> {
    let minor = fd_to_minor(fd)?;
    let ttys = TTYS.lock();
    let tty = ttys.get(&minor).ok_or("tty not found")?;
    let mut tty_guard = tty.lock();
    if termios.len() >= 60 {
        tty_guard.termios.c_iflag =
            u32::from_ne_bytes([termios[0], termios[1], termios[2], termios[3]]);
        tty_guard.termios.c_oflag =
            u32::from_ne_bytes([termios[4], termios[5], termios[6], termios[7]]);
        tty_guard.termios.c_cflag =
            u32::from_ne_bytes([termios[8], termios[9], termios[10], termios[11]]);
        tty_guard.termios.c_lflag =
            u32::from_ne_bytes([termios[12], termios[13], termios[14], termios[15]]);
    }
    Ok(())
}

pub fn set_window_size(fd: i32, rows: u16, cols: u16) -> Result<(), &'static str> {
    let minor = fd_to_minor(fd)?;
    let ttys = TTYS.lock();
    let tty = ttys.get(&minor).ok_or("tty not found")?;
    let mut tty_guard = tty.lock();
    tty_guard.winsize.ws_row = rows;
    tty_guard.winsize.ws_col = cols;
    Ok(())
}

pub fn set_foreground_pgrp(fd: i32, pgrp: i32) -> Result<(), &'static str> {
    let minor = fd_to_minor(fd)?;
    let ttys = TTYS.lock();
    let tty = ttys.get(&minor).ok_or("tty not found")?;
    let mut tty_guard = tty.lock();
    tty_guard.pgrp = pgrp;
    Ok(())
}

fn fd_to_minor(fd: i32) -> Result<u32, &'static str> {
    if fd <= 2 {
        Ok(0)
    } else {
        Ok(fd as u32 - 3)
    }
}
