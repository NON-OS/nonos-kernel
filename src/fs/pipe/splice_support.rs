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

use alloc::sync::Arc;
use alloc::vec;
use spin::Mutex;
use super::buffer::PipeBuffer;

pub fn pipe_splice_read(buffer: &Arc<Mutex<PipeBuffer>>, len: usize, flags: u32) -> Result<alloc::vec::Vec<u8>, i32> {
    let mut buf = vec![0u8; len];
    let mut pipe_buf = buffer.lock();
    let n = pipe_buf.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

pub fn pipe_splice_write(buffer: &Arc<Mutex<PipeBuffer>>, data: &[u8], flags: u32) -> Result<usize, i32> {
    let mut pipe_buf = buffer.lock();
    pipe_buf.write(data)
}

pub fn pipe_tee(src: &Arc<Mutex<PipeBuffer>>, dst: &Arc<Mutex<PipeBuffer>>, len: usize, flags: u32) -> Result<usize, i32> {
    let src_buf = src.lock();
    let src_len = src_buf.len();
    if src_len == 0 {
        return if (flags & 0x01) != 0 { Err(-11) } else { Ok(0) };
    }
    let to_copy = len.min(src_len);
    let head = src_buf.head.load(core::sync::atomic::Ordering::SeqCst);
    let tail = src_buf.tail.load(core::sync::atomic::Ordering::SeqCst);
    let cap = src_buf.capacity;
    let mut data = vec![0u8; to_copy];
    for i in 0..to_copy {
        let idx = (tail + i) % cap;
        data[i] = src_buf.data[idx];
    }
    drop(src_buf);
    let mut dst_buf = dst.lock();
    dst_buf.write(&data)
}

pub fn pipe_vmsplice_to(buffer: &Arc<Mutex<PipeBuffer>>, iov: &[(u64, usize)], flags: u32) -> Result<usize, i32> {
    let mut total = 0;
    for &(base, len) in iov {
        let mut buf = vec![0u8; len];
        crate::usercopy::copy_from_user(base, &mut buf)?;
        let n = pipe_splice_write(buffer, &buf, flags)?;
        total += n;
        if n < len {
            break;
        }
    }
    Ok(total)
}

pub fn pipe_vmsplice_from(buffer: &Arc<Mutex<PipeBuffer>>, iov: &[(u64, usize)], flags: u32) -> Result<usize, i32> {
    let mut total = 0;
    for &(base, len) in iov {
        let data = pipe_splice_read(buffer, len, flags)?;
        crate::usercopy::copy_to_user(base, &data)?;
        total += data.len();
        if data.len() < len {
            break;
        }
    }
    Ok(total)
}
