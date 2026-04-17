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
use alloc::collections::VecDeque;
use spin::Mutex;
use super::socket::{UnixSocket, UnixSocketType};

pub struct UnixStream {
    pub socket: Arc<UnixSocket>,
    pub recv_buf: Mutex<VecDeque<u8>>,
    pub connected: core::sync::atomic::AtomicBool,
}

impl UnixStream {
    pub fn new(flags: u32) -> Self {
        Self {
            socket: Arc::new(UnixSocket::new(UnixSocketType::Stream, flags)),
            recv_buf: Mutex::new(VecDeque::with_capacity(65536)),
            connected: core::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, i32> {
        let mut recv = self.recv_buf.lock();
        if recv.is_empty() {
            if !self.connected.load(core::sync::atomic::Ordering::SeqCst) {
                return Ok(0);
            }
            return Err(-11);
        }
        let len = buf.len().min(recv.len());
        for i in 0..len {
            if let Some(byte) = recv.pop_front() {
                buf[i] = byte;
            }
        }
        Ok(len)
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, i32> {
        if !self.connected.load(core::sync::atomic::Ordering::SeqCst) {
            return Err(-107);
        }
        self.socket.send(buf, None)
    }

    pub fn shutdown(&self, how: i32) -> Result<(), i32> {
        const SHUT_RD: i32 = 0;
        const SHUT_WR: i32 = 1;
        const SHUT_RDWR: i32 = 2;
        match how {
            SHUT_RD => {
                self.recv_buf.lock().clear();
            }
            SHUT_WR => {
                self.connected.store(false, core::sync::atomic::Ordering::SeqCst);
            }
            SHUT_RDWR => {
                self.recv_buf.lock().clear();
                self.connected.store(false, core::sync::atomic::Ordering::SeqCst);
            }
            _ => return Err(-22),
        }
        Ok(())
    }
}

pub fn stream_connect(client: &Arc<UnixSocket>, server_path: &str) -> Result<Arc<UnixSocket>, i32> {
    let server = super::listen::lookup_bound_socket(server_path)?;
    if !server.listening.load(core::sync::atomic::Ordering::SeqCst) {
        return Err(-111);
    }
    let peer = Arc::new(UnixSocket::new(UnixSocketType::Stream, 0));
    client.connect(peer.clone())?;
    peer.connect(client.clone())?;
    server.backlog.lock().push_back(peer.clone());
    Ok(peer)
}

pub fn stream_accept(listener: &Arc<UnixSocket>) -> Result<Arc<UnixSocket>, i32> {
    if !listener.listening.load(core::sync::atomic::Ordering::SeqCst) {
        return Err(-22);
    }
    listener.backlog.lock().pop_front().ok_or(-11)
}
