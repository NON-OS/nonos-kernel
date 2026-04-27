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

use super::super::super::error::AudioError;
use super::super::stream;
use super::structure::HdAudioController;
use core::ptr;
use core::sync::atomic::Ordering;

impl HdAudioController {
    pub fn record_pcm(&self, buffer: &mut [u8]) -> Result<usize, AudioError> {
        if !self.input_enabled {
            return Err(AudioError::NoInputDevice);
        }
        stream::start_stream(self, self.in_stream);
        if let Err(e) = stream::wait_record_complete(self, self.in_stream) {
            self.errors.fetch_add(1, Ordering::Relaxed);
            stream::stop_stream(self, self.in_stream);
            return Err(e);
        }
        let n = core::cmp::min(buffer.len(), self.in_pcm_buf.len());
        unsafe {
            ptr::copy_nonoverlapping(self.in_pcm_buf.as_ptr::<u8>(), buffer.as_mut_ptr(), n);
        }
        self.bytes_recorded.fetch_add(n as u64, Ordering::Relaxed);
        stream::stop_stream(self, self.in_stream);
        Ok(n)
    }

    pub fn is_recording_supported(&self) -> bool {
        self.input_enabled && self.caps.input_streams > 0
    }
}
