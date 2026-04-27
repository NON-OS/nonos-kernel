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
use super::ldisc::LineDiscipline;
use super::termios::{ECHO, ICANON, ICRNL, IGNCR, INLCR, ONLCR, OPOST};
use alloc::collections::VecDeque;
use spin::Mutex;

const N_TTY_BUF_SIZE: usize = 4096;

pub struct NTtyLdisc {
    read_buf: Mutex<VecDeque<u8>>,
    canon_buf: Mutex<VecDeque<u8>>,
}

impl NTtyLdisc {
    pub fn new() -> Self {
        Self {
            read_buf: Mutex::new(VecDeque::with_capacity(N_TTY_BUF_SIZE)),
            canon_buf: Mutex::new(VecDeque::with_capacity(N_TTY_BUF_SIZE)),
        }
    }

    fn process_input(&self, tty: &TtyStruct, c: u8) -> Option<u8> {
        let iflag = tty.termios.c_iflag;
        if c == b'\r' && (iflag & ICRNL) != 0 {
            return Some(b'\n');
        }
        if c == b'\n' && (iflag & INLCR) != 0 {
            return Some(b'\r');
        }
        if c == b'\r' && (iflag & IGNCR) != 0 {
            return None;
        }
        Some(c)
    }

    fn process_output(&self, tty: &TtyStruct, c: u8) -> alloc::vec::Vec<u8> {
        let oflag = tty.termios.c_oflag;
        if (oflag & OPOST) == 0 {
            return alloc::vec![c];
        }
        if c == b'\n' && (oflag & ONLCR) != 0 {
            return alloc::vec![b'\r', b'\n'];
        }
        alloc::vec![c]
    }
}

impl LineDiscipline for NTtyLdisc {
    fn open(&self, _tty: &mut TtyStruct) -> Result<(), i32> {
        Ok(())
    }
    fn close(&self, _tty: &mut TtyStruct) -> Result<(), i32> {
        Ok(())
    }

    fn read(&self, tty: &mut TtyStruct, buf: &mut [u8]) -> Result<usize, i32> {
        let canonical = (tty.termios.c_lflag & ICANON) != 0;
        let mut read_buf = if canonical { self.canon_buf.lock() } else { self.read_buf.lock() };
        let mut count = 0;
        for byte in buf.iter_mut() {
            if let Some(c) = read_buf.pop_front() {
                *byte = c;
                count += 1;
                if canonical && c == b'\n' {
                    break;
                }
            } else {
                break;
            }
        }
        if count == 0 {
            return Err(-11);
        }
        Ok(count)
    }

    fn write(&self, tty: &mut TtyStruct, buf: &[u8]) -> Result<usize, i32> {
        let mut output = alloc::vec::Vec::new();
        for &c in buf {
            output.extend(self.process_output(tty, c));
        }
        tty.driver.ops.write(tty, &output)
    }

    fn receive_buf(&self, tty: &mut TtyStruct, buf: &[u8], _flags: &[u8]) {
        let canonical = (tty.termios.c_lflag & ICANON) != 0;
        let echo = (tty.termios.c_lflag & ECHO) != 0;
        let mut read_buf = if canonical { self.canon_buf.lock() } else { self.read_buf.lock() };
        for &c in buf {
            if let Some(processed) = self.process_input(tty, c) {
                read_buf.push_back(processed);
                if echo {
                    let _ = tty.driver.ops.write(tty, &[processed]);
                }
            }
        }
    }

    fn write_wakeup(&self, _tty: &TtyStruct) {}
    fn ioctl(&self, _tty: &mut TtyStruct, _cmd: u32, _arg: u64) -> Result<i64, i32> {
        Err(-25)
    }
    fn poll(&self, _tty: &TtyStruct) -> u32 {
        let has_data = !self.read_buf.lock().is_empty() || !self.canon_buf.lock().is_empty();
        if has_data {
            0x01 | 0x04
        } else {
            0x04
        }
    }
    fn flush_buffer(&self, _tty: &mut TtyStruct) {
        self.read_buf.lock().clear();
        self.canon_buf.lock().clear();
    }
}
