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
use super::socket::{UnixSocket, UnixSocketType, UnixMessage};

pub struct UnixSeqpacket {
    pub socket: Arc<UnixSocket>,
    pub msg_queue: Mutex<VecDeque<alloc::vec::Vec<u8>>>,
    pub connected: core::sync::atomic::AtomicBool,
}

impl UnixSeqpacket {
    pub fn new(flags: u32) -> Self {
        Self {
            socket: Arc::new(UnixSocket::new(UnixSocketType::Seqpacket, flags)),
            msg_queue: Mutex::new(VecDeque::with_capacity(64)),
            connected: core::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn send(&self, buf: &[u8]) -> Result<usize, i32> {
        if !self.connected.load(core::sync::atomic::Ordering::SeqCst) {
            return Err(-107);
        }
        self.socket.send(buf, None)
    }

    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, i32> {
        if !self.connected.load(core::sync::atomic::Ordering::SeqCst) {
            return Err(-107);
        }
        let (len, _) = self.socket.recv(buf)?;
        Ok(len)
    }

    pub fn shutdown(&self, how: i32) -> Result<(), i32> {
        self.connected.store(false, core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

pub fn seqpacket_connect(client: &Arc<UnixSocket>, server_path: &str) -> Result<Arc<UnixSocket>, i32> {
    let server = super::listen::lookup_bound_socket(server_path)?;
    if !server.listening.load(core::sync::atomic::Ordering::SeqCst) {
        return Err(-111);
    }
    if server.socket_type != UnixSocketType::Seqpacket {
        return Err(-91);
    }
    let peer = Arc::new(UnixSocket::new(UnixSocketType::Seqpacket, 0));
    client.connect(peer.clone())?;
    peer.connect(client.clone())?;
    server.backlog.lock().push_back(peer.clone());
    Ok(peer)
}

pub fn seqpacket_accept(listener: &Arc<UnixSocket>) -> Result<Arc<UnixSocket>, i32> {
    if !listener.listening.load(core::sync::atomic::Ordering::SeqCst) {
        return Err(-22);
    }
    if listener.socket_type != UnixSocketType::Seqpacket {
        return Err(-91);
    }
    listener.backlog.lock().pop_front().ok_or(-11)
}
