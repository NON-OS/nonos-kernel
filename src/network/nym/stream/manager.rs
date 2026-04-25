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

use super::nym_stream::NymStream;
use crate::network::nym::error::NymError;
use crate::network::nym::types::NymAddress;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::{Mutex, Once};

static STREAM_MANAGER: Once<Mutex<StreamManager>> = Once::new();
static NEXT_STREAM_ID: AtomicU32 = AtomicU32::new(1);

pub struct StreamManager {
    streams: BTreeMap<u32, NymStream>,
    max_streams: usize,
}

pub fn get_stream_manager() -> &'static Mutex<StreamManager> {
    STREAM_MANAGER.call_once(|| Mutex::new(StreamManager::new(256)))
}

impl StreamManager {
    pub fn new(max_streams: usize) -> Self {
        Self { streams: BTreeMap::new(), max_streams }
    }

    pub fn create_stream(&mut self, destination: NymAddress) -> Result<u32, NymError> {
        if self.streams.len() >= self.max_streams {
            return Err(NymError::BufferFull);
        }
        let id = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
        let stream = NymStream::new(id, destination)?;
        self.streams.insert(id, stream);
        Ok(id)
    }

    pub fn get_stream(&self, id: u32) -> Option<&NymStream> {
        self.streams.get(&id)
    }

    pub fn get_stream_mut(&mut self, id: u32) -> Option<&mut NymStream> {
        self.streams.get_mut(&id)
    }

    pub fn close_stream(&mut self, id: u32) {
        if let Some(mut stream) = self.streams.remove(&id) {
            stream.close();
        }
    }

    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
}
