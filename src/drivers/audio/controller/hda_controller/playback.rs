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

use super::super::super::constants::*;
use super::super::super::error::AudioError;
use super::super::helpers::RegisterAccess;
use super::super::stream;
use super::structure::HdAudioController;
use core::ptr;
use core::sync::atomic::Ordering;

impl HdAudioController {
    pub fn play_pcm(&self, data: &[u8]) -> Result<(), AudioError> {
        let n = core::cmp::min(data.len(), self.pcm_buf.len());
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), self.pcm_buf.as_mut_ptr::<u8>(), n);
        }
        stream::start_stream(self, self.out_stream);
        if let Err(e) = stream::wait_playback_complete(self, self.out_stream) {
            self.check_stream_errors(self.out_stream);
            self.errors.fetch_add(1, Ordering::Relaxed);
            stream::stop_stream(self, self.out_stream);
            return Err(e);
        }
        self.check_stream_errors(self.out_stream);
        self.bytes_played.fetch_add(n as u64, Ordering::Relaxed);
        stream::stop_stream(self, self.out_stream);
        Ok(())
    }

    pub(super) fn check_stream_errors(&self, stream_index: u8) {
        let status = self.read_stream_reg8(stream_index, SD_STS);
        if status & SD_STS_FIFOE != 0 {
            self.underruns.fetch_add(1, Ordering::Relaxed);
            self.write_stream_reg8(stream_index, SD_STS, SD_STS_FIFOE);
        }
        if status & SD_STS_DESE != 0 {
            self.overruns.fetch_add(1, Ordering::Relaxed);
            self.write_stream_reg8(stream_index, SD_STS, SD_STS_DESE);
        }
    }

    #[inline]
    pub fn is_playing(&self) -> bool {
        stream::is_stream_running(self, self.out_stream)
    }
}
