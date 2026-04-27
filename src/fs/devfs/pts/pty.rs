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

use crate::fs::devfs::types::DeviceOps;
use alloc::sync::Arc;

pub struct PtySlaveDevice {
    pub pty_num: u32,
}

impl DeviceOps for PtySlaveDevice {
    fn open(&self, _flags: u32) -> Result<(), i32> {
        crate::tty::pty::slave_open(self.pty_num)
    }

    fn close(&self) -> Result<(), i32> {
        crate::tty::pty::slave_close(self.pty_num)
    }

    fn read(&self, buf: &mut [u8], _offset: u64) -> Result<usize, i32> {
        crate::tty::pty::slave_read(self.pty_num, buf)
    }

    fn write(&self, buf: &[u8], _offset: u64) -> Result<usize, i32> {
        crate::tty::pty::slave_write(self.pty_num, buf)
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<i64, i32> {
        crate::tty::pty::slave_ioctl(self.pty_num, cmd, arg)
    }

    fn poll(&self) -> u32 {
        crate::tty::pty::slave_poll(self.pty_num)
    }
}

pub fn get_slave_ops(pty_num: u32) -> Arc<dyn DeviceOps> {
    Arc::new(PtySlaveDevice { pty_num })
}
