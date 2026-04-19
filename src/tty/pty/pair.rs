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

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use spin::Mutex;
use core::sync::atomic::AtomicBool;
use crate::tty::driver::TtyStruct;
use crate::tty::buffer::TtyBuffer;

static PTY_PAIRS: Mutex<BTreeMap<u32, Arc<PtyPair>>> = Mutex::new(BTreeMap::new());

pub struct PtyPair {
    pub num: u32,
    pub master_buf: Mutex<TtyBuffer>,
    pub slave_buf: Mutex<TtyBuffer>,
    pub slave_tty: Mutex<TtyStruct>,
    pub unlocked: AtomicBool,
}

pub fn create_pair(num: u32) -> Result<(), i32> {
    let driver = crate::tty::driver::get_driver("pty").ok_or(-6)?;
    let ldisc = crate::tty::ldisc::get_ldisc(0).ok_or(-6)?;
    let tty = TtyStruct {
        index: num,
        driver,
        termios: crate::tty::termios::Termios::default(),
        winsize: crate::tty::termios::Winsize::new(24, 80),
        ldisc,
        pgrp: 0,
        session: 0,
    };
    let pair = Arc::new(PtyPair {
        num,
        master_buf: Mutex::new(TtyBuffer::new()),
        slave_buf: Mutex::new(TtyBuffer::new()),
        slave_tty: Mutex::new(tty),
        unlocked: AtomicBool::new(false),
    });
    PTY_PAIRS.lock().insert(num, pair);
    Ok(())
}

pub fn destroy_pair(num: u32) {
    PTY_PAIRS.lock().remove(&num);
}

pub fn get_pair(num: u32) -> Option<Arc<PtyPair>> {
    PTY_PAIRS.lock().get(&num).cloned()
}

pub fn pair_exists(num: u32) -> bool {
    PTY_PAIRS.lock().contains_key(&num)
}
