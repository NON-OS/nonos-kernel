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

use super::buffer::PipeBuffer;
use alloc::sync::Arc;
use spin::Mutex;

pub struct PipeWriter {
    buffer: Arc<Mutex<PipeBuffer>>,
    flags: u32,
}

impl PipeWriter {
    pub fn new(buffer: Arc<Mutex<PipeBuffer>>, flags: u32) -> Self {
        Self { buffer, flags }
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, i32> {
        self.buffer.lock().write(buf)
    }

    pub fn poll(&self) -> u32 {
        let buffer = self.buffer.lock();
        let mut events = 0u32;
        if buffer.available_write() > 0 {
            events |= 0x04;
        }
        if !buffer.has_readers() {
            events |= 0x08;
        }
        events
    }

    pub fn is_nonblocking(&self) -> bool {
        (self.flags & 0x800) != 0
    }

    pub fn close(&self) {
        self.buffer.lock().remove_writer();
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        self.buffer.lock().remove_writer();
    }
}

pub fn pipe_write(buffer: &Arc<Mutex<PipeBuffer>>, buf: &[u8], flags: u32) -> Result<usize, i32> {
    let mut pipe_buf = buffer.lock();
    let result = pipe_buf.write(buf);
    if result == Err(-11) && (flags & 0x800) == 0 {
        drop(pipe_buf);
        loop {
            crate::sched::yield_now();
            let mut pipe_buf = buffer.lock();
            match pipe_buf.write(buf) {
                Ok(n) => return Ok(n),
                Err(-11) if pipe_buf.has_readers() => continue,
                Err(e) => return Err(e),
            }
        }
    }
    result
}
