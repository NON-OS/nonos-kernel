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

use super::socket::{UnixMessage, UnixSocket, UnixSocketType};
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use spin::Mutex;

pub struct UnixDgram {
    pub socket: Arc<UnixSocket>,
    pub recv_queue: Mutex<VecDeque<(alloc::vec::Vec<u8>, Option<String>)>>,
}

impl UnixDgram {
    pub fn new(flags: u32) -> Self {
        Self {
            socket: Arc::new(UnixSocket::new(UnixSocketType::Dgram, flags)),
            recv_queue: Mutex::new(VecDeque::with_capacity(128)),
        }
    }

    pub fn sendto(&self, buf: &[u8], dest_path: &str) -> Result<usize, i32> {
        let dest = super::listen::lookup_bound_socket(dest_path)?;
        let src_path = self.socket.bound_path.lock().clone();
        let anc_data = src_path.map(|p| super::ancillary::AncillaryData::from_path(&p));
        dest.recv_buf.lock().push_back(UnixMessage { data: buf.to_vec(), ancillary: anc_data });
        Ok(buf.len())
    }

    pub fn send(&self, buf: &[u8]) -> Result<usize, i32> {
        let peer = self.socket.peer.lock().clone().ok_or(-107)?;
        peer.recv_buf.lock().push_back(UnixMessage { data: buf.to_vec(), ancillary: None });
        Ok(buf.len())
    }

    pub fn recvfrom(&self, buf: &mut [u8]) -> Result<(usize, Option<String>), i32> {
        let mut queue = self.recv_queue.lock();
        if let Some((data, src)) = queue.pop_front() {
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            return Ok((len, src));
        }
        let msg = self.socket.recv_buf.lock().pop_front().ok_or(-11)?;
        let len = msg.data.len().min(buf.len());
        buf[..len].copy_from_slice(&msg.data[..len]);
        Ok((len, None))
    }

    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, i32> {
        self.recvfrom(buf).map(|(n, _)| n)
    }
}

pub fn dgram_send(socket: &Arc<UnixSocket>, buf: &[u8], dest: Option<&str>) -> Result<usize, i32> {
    if let Some(path) = dest {
        let dest_sock = super::listen::lookup_bound_socket(path)?;
        dest_sock.recv_buf.lock().push_back(UnixMessage { data: buf.to_vec(), ancillary: None });
    } else {
        socket.send(buf, None)?;
    }
    Ok(buf.len())
}

pub fn dgram_recv(
    socket: &Arc<UnixSocket>,
    buf: &mut [u8],
) -> Result<(usize, Option<String>), i32> {
    let (len, anc) = socket.recv(buf)?;
    let src_path = anc.and_then(|a| a.get_source_path());
    Ok((len, src_path))
}
