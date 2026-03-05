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

//! Pipe IPC implementation
//!
//! Provides anonymous pipes for inter-process communication.
//! Pipes are unidirectional byte streams with a read end and write end.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

// =============================================================================
// Constants
// =============================================================================

/// Default pipe buffer size (64KB)
pub const PIPE_BUF_SIZE: usize = 65536;

/// Maximum number of pipes
const MAX_PIPES: usize = 1024;

// Error codes
const EAGAIN: i32 = 11;
const EPIPE: i32 = 32;
const EBADF: i32 = 9;

// =============================================================================
// Pipe State
// =============================================================================

/// A pipe instance
struct Pipe {
    /// Unique pipe ID
    id: u32,
    /// Circular buffer for data
    buffer: Vec<u8>,
    /// Read position in buffer
    read_pos: usize,
    /// Write position in buffer
    write_pos: usize,
    /// Number of bytes in buffer
    bytes_available: usize,
    /// Buffer capacity
    capacity: usize,
    /// Is read end closed?
    read_closed: bool,
    /// Is write end closed?
    write_closed: bool,
    /// Non-blocking mode for read end
    read_nonblock: bool,
    /// Non-blocking mode for write end
    write_nonblock: bool,
}

impl Pipe {
    fn new(id: u32, capacity: usize) -> Self {
        Self {
            id,
            buffer: vec![0u8; capacity],
            read_pos: 0,
            write_pos: 0,
            bytes_available: 0,
            capacity,
            read_closed: false,
            write_closed: false,
            read_nonblock: false,
            write_nonblock: false,
        }
    }

    /// Returns the unique pipe identifier
    fn pipe_id(&self) -> u32 {
        self.id
    }

    /// Check if pipe is broken (write end closed, no data)
    fn is_broken(&self) -> bool {
        self.write_closed && self.bytes_available == 0
    }

    /// Space available for writing
    fn space_available(&self) -> usize {
        self.capacity - self.bytes_available
    }

    /// Read data from pipe
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, i32> {
        if self.bytes_available == 0 {
            if self.write_closed {
                return Ok(0); // EOF
            }
            if self.read_nonblock {
                return Err(EAGAIN);
            }
            // Would block - for now return EAGAIN
            return Err(EAGAIN);
        }

        let to_read = buf.len().min(self.bytes_available);
        let mut read = 0;

        while read < to_read {
            buf[read] = self.buffer[self.read_pos];
            self.read_pos = (self.read_pos + 1) % self.capacity;
            read += 1;
        }

        self.bytes_available -= read;
        Ok(read)
    }

    /// Write data to pipe
    fn write(&mut self, buf: &[u8]) -> Result<usize, i32> {
        if self.read_closed {
            return Err(EPIPE); // Broken pipe
        }

        if self.space_available() == 0 {
            if self.write_nonblock {
                return Err(EAGAIN);
            }
            // Would block - for now return EAGAIN
            return Err(EAGAIN);
        }

        let to_write = buf.len().min(self.space_available());
        let mut written = 0;

        while written < to_write {
            self.buffer[self.write_pos] = buf[written];
            self.write_pos = (self.write_pos + 1) % self.capacity;
            written += 1;
        }

        self.bytes_available += written;
        Ok(written)
    }
}

// =============================================================================
// Global Registry
// =============================================================================

/// Global pipe registry
static PIPES: Mutex<BTreeMap<u32, Pipe>> = Mutex::new(BTreeMap::new());
static NEXT_PIPE_ID: AtomicU32 = AtomicU32::new(1);

/// FD to pipe ID + is_read_end mapping
static FD_TO_PIPE: Mutex<BTreeMap<i32, (u32, bool)>> = Mutex::new(BTreeMap::new());
static NEXT_FD: AtomicU32 = AtomicU32::new(4000);

/// Allocate a new file descriptor
fn allocate_fd() -> i32 {
    NEXT_FD.fetch_add(1, Ordering::SeqCst) as i32
}

// =============================================================================
// Public API
// =============================================================================

/// Create a new pipe, returning (read_fd, write_fd)
pub fn create_pipe() -> Result<(i32, i32), i32> {
    create_pipe_with_size(PIPE_BUF_SIZE)
}

/// Create a new pipe with specified buffer size
pub fn create_pipe_with_size(size: usize) -> Result<(i32, i32), i32> {
    let pipes = PIPES.lock();
    if pipes.len() >= MAX_PIPES {
        drop(pipes);
        return Err(24); // EMFILE
    }
    drop(pipes);

    let pipe_id = NEXT_PIPE_ID.fetch_add(1, Ordering::SeqCst);
    let pipe = Pipe::new(pipe_id, size);

    PIPES.lock().insert(pipe_id, pipe);

    let read_fd = allocate_fd();
    let write_fd = allocate_fd();

    let mut fd_map = FD_TO_PIPE.lock();
    fd_map.insert(read_fd, (pipe_id, true));  // read end
    fd_map.insert(write_fd, (pipe_id, false)); // write end

    Ok((read_fd, write_fd))
}

/// Read from a pipe
pub fn pipe_read(fd: i32, buf: &mut [u8]) -> Result<usize, i32> {
    let (pipe_id, is_read_end) = match FD_TO_PIPE.lock().get(&fd) {
        Some(&info) => info,
        None => return Err(EBADF),
    };

    if !is_read_end {
        return Err(EBADF); // Can't read from write end
    }

    let mut pipes = PIPES.lock();
    match pipes.get_mut(&pipe_id) {
        Some(pipe) => pipe.read(buf),
        None => Err(EBADF),
    }
}

/// Write to a pipe
pub fn pipe_write(fd: i32, buf: &[u8]) -> Result<usize, i32> {
    let (pipe_id, is_read_end) = match FD_TO_PIPE.lock().get(&fd) {
        Some(&info) => info,
        None => return Err(EBADF),
    };

    if is_read_end {
        return Err(EBADF); // Can't write to read end
    }

    let mut pipes = PIPES.lock();
    match pipes.get_mut(&pipe_id) {
        Some(pipe) => pipe.write(buf),
        None => Err(EBADF),
    }
}

/// Close a pipe file descriptor
pub fn pipe_close(fd: i32) -> Result<(), i32> {
    let (pipe_id, is_read_end) = match FD_TO_PIPE.lock().remove(&fd) {
        Some(info) => info,
        None => return Err(EBADF),
    };

    let mut pipes = PIPES.lock();
    if let Some(pipe) = pipes.get_mut(&pipe_id) {
        if is_read_end {
            pipe.read_closed = true;
        } else {
            pipe.write_closed = true;
        }

        // Remove pipe if both ends closed
        if pipe.read_closed && pipe.write_closed {
            pipes.remove(&pipe_id);
        }
    }

    Ok(())
}

/// Set non-blocking mode for a pipe fd
pub fn pipe_set_nonblock(fd: i32, nonblock: bool) -> Result<(), i32> {
    let (pipe_id, is_read_end) = match FD_TO_PIPE.lock().get(&fd) {
        Some(&info) => info,
        None => return Err(EBADF),
    };

    let mut pipes = PIPES.lock();
    if let Some(pipe) = pipes.get_mut(&pipe_id) {
        if is_read_end {
            pipe.read_nonblock = nonblock;
        } else {
            pipe.write_nonblock = nonblock;
        }
        Ok(())
    } else {
        Err(EBADF)
    }
}

// =============================================================================
// Polling Support
// =============================================================================

/// Information about a pipe for polling
pub struct PipeInfo {
    pub bytes_available: usize,
    pub space_available: usize,
    pub is_broken: bool,
}

/// Get pipe info for polling (used by epoll/select/poll)
pub fn get_pipe_info(pipe_id: usize) -> Option<PipeInfo> {
    let pipes = PIPES.lock();
    pipes.get(&(pipe_id as u32)).map(|pipe| PipeInfo {
        bytes_available: pipe.bytes_available,
        space_available: pipe.space_available(),
        is_broken: pipe.is_broken(),
    })
}

/// Check if pipe fd is readable
pub fn pipe_is_readable(fd: i32) -> bool {
    let (pipe_id, is_read_end) = match FD_TO_PIPE.lock().get(&fd) {
        Some(&info) => info,
        None => return false,
    };

    if !is_read_end {
        return false;
    }

    let pipes = PIPES.lock();
    pipes.get(&pipe_id)
        .map(|p| p.bytes_available > 0 || p.write_closed)
        .unwrap_or(false)
}

/// Check if pipe fd is writable
pub fn pipe_is_writable(fd: i32) -> bool {
    let (pipe_id, is_read_end) = match FD_TO_PIPE.lock().get(&fd) {
        Some(&info) => info,
        None => return false,
    };

    if is_read_end {
        return false;
    }

    let pipes = PIPES.lock();
    pipes.get(&pipe_id)
        .map(|p| p.space_available() > 0 && !p.read_closed)
        .unwrap_or(false)
}

/// Get pipe ID from file descriptor
pub fn fd_to_pipe_id(fd: i32) -> Option<(u32, bool)> {
    FD_TO_PIPE.lock().get(&fd).copied()
}

/// Check if fd is a pipe
pub fn is_pipe(fd: i32) -> bool {
    FD_TO_PIPE.lock().contains_key(&fd)
}

/// Get the internal pipe ID for debugging/diagnostics
pub fn get_pipe_internal_id(pipe_id: u32) -> Option<u32> {
    let pipes = PIPES.lock();
    pipes.get(&pipe_id).map(|p| p.pipe_id())
}

// =============================================================================
// Statistics
// =============================================================================

/// Get number of active pipes
pub fn pipe_count() -> usize {
    PIPES.lock().len()
}

/// Get statistics about pipe subsystem
pub fn get_pipe_stats() -> PipeStats {
    let pipes = PIPES.lock();
    let mut total_bytes = 0;
    let mut total_capacity = 0;

    for pipe in pipes.values() {
        total_bytes += pipe.bytes_available;
        total_capacity += pipe.capacity;
    }

    PipeStats {
        active_count: pipes.len(),
        total_bytes_buffered: total_bytes,
        total_capacity,
    }
}

/// Pipe subsystem statistics
pub struct PipeStats {
    pub active_count: usize,
    pub total_bytes_buffered: usize,
    pub total_capacity: usize,
}
