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

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::AtomicU32;
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixSocketType {
    Stream,
    Dgram,
    Seqpacket,
}

pub struct UnixSocket {
    pub socket_type: UnixSocketType,
    pub flags: AtomicU32,
    pub bound_path: Mutex<Option<String>>,
    pub peer: Mutex<Option<Arc<UnixSocket>>>,
    pub recv_buf: Mutex<VecDeque<UnixMessage>>,
    pub send_buf: Mutex<VecDeque<UnixMessage>>,
    pub backlog: Mutex<VecDeque<Arc<UnixSocket>>>,
    pub backlog_limit: core::sync::atomic::AtomicUsize,
    pub listening: core::sync::atomic::AtomicBool,
}

pub struct UnixMessage {
    pub data: alloc::vec::Vec<u8>,
    pub ancillary: Option<super::ancillary::AncillaryData>,
}

impl UnixSocket {
    pub fn new(socket_type: UnixSocketType, flags: u32) -> Self {
        Self {
            socket_type,
            flags: AtomicU32::new(flags),
            bound_path: Mutex::new(None),
            peer: Mutex::new(None),
            recv_buf: Mutex::new(VecDeque::new()),
            send_buf: Mutex::new(VecDeque::new()),
            backlog: Mutex::new(VecDeque::new()),
            backlog_limit: core::sync::atomic::AtomicUsize::new(128),
            listening: core::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn set_backlog_limit(&self, limit: usize) {
        self.backlog_limit.store(limit, core::sync::atomic::Ordering::SeqCst);
    }

    pub fn get_backlog_limit(&self) -> usize {
        self.backlog_limit.load(core::sync::atomic::Ordering::SeqCst)
    }

    pub fn can_accept_connection(&self) -> bool {
        self.backlog.lock().len() < self.get_backlog_limit()
    }

    pub fn bind(&self, path: &str) -> Result<(), i32> {
        let mut bound = self.bound_path.lock();
        if bound.is_some() {
            return Err(-22);
        }
        *bound = Some(String::from(path));
        super::listen::register_bound_socket(path, self as *const _ as u64)?;
        Ok(())
    }

    pub fn connect(&self, peer: Arc<UnixSocket>) -> Result<(), i32> {
        let mut p = self.peer.lock();
        if p.is_some() {
            return Err(-106);
        }
        *p = Some(peer);
        Ok(())
    }

    pub fn send(
        &self,
        data: &[u8],
        ancillary: Option<super::ancillary::AncillaryData>,
    ) -> Result<usize, i32> {
        let peer = self.peer.lock().clone().ok_or(-107)?;
        peer.recv_buf.lock().push_back(UnixMessage { data: data.to_vec(), ancillary });
        Ok(data.len())
    }

    pub fn recv(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, Option<super::ancillary::AncillaryData>), i32> {
        let msg = self.recv_buf.lock().pop_front().ok_or(-11)?;
        let len = msg.data.len().min(buf.len());
        buf[..len].copy_from_slice(&msg.data[..len]);
        Ok((len, msg.ancillary))
    }

    pub fn poll(&self) -> u32 {
        let mut events = 0u32;
        if !self.recv_buf.lock().is_empty() {
            events |= 0x01;
        }
        if self.peer.lock().is_some() {
            events |= 0x04;
        }
        if !self.backlog.lock().is_empty() {
            events |= 0x01;
        }
        events
    }
}
