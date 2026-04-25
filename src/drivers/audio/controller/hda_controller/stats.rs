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

use super::super::super::types::{AudioFormat, AudioStats};
use super::super::init;
use super::super::stream;
use super::structure::HdAudioController;
use core::sync::atomic::Ordering;

impl HdAudioController {
    pub fn get_stats(&self) -> AudioStats {
        let bytes = self.bytes_played.load(Ordering::Relaxed);
        let recorded = self.bytes_recorded.load(Ordering::Relaxed);
        let bps = self.format.bytes_per_sample() as u64;
        let mut active = 0u64;
        if stream::is_stream_running(self, self.out_stream) {
            active += 1;
        }
        if self.input_enabled && stream::is_stream_running(self, self.in_stream) {
            active += 1;
        }
        AudioStats {
            samples_played: if bps > 0 { bytes / bps } else { 0 },
            samples_recorded: if bps > 0 { recorded / bps } else { 0 },
            buffer_underruns: self.underruns.load(Ordering::Relaxed),
            buffer_overruns: self.overruns.load(Ordering::Relaxed),
            interrupts_handled: 0,
            active_streams: active,
            codecs_detected: self.codec_mask.count_ones(),
            bytes_transferred: bytes + recorded,
            error_count: self.errors.load(Ordering::Relaxed),
        }
    }

    #[inline]
    pub fn output_streams(&self) -> u8 {
        self.caps.output_streams
    }
    #[inline]
    pub fn input_streams(&self) -> u8 {
        self.caps.input_streams
    }
    #[inline]
    pub fn codec_mask(&self) -> u16 {
        self.codec_mask
    }
    #[inline]
    pub fn primary_codec(&self) -> Option<u8> {
        self.primary_codec
    }
    #[inline]
    pub fn format(&self) -> AudioFormat {
        self.format
    }
    #[inline]
    pub fn buffer_size(&self) -> usize {
        self.pcm_buf.len()
    }
    #[inline]
    pub fn bytes_played(&self) -> u64 {
        self.bytes_played.load(Ordering::Relaxed)
    }
    #[inline]
    pub fn error_count(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }
    #[inline]
    pub fn is_ready(&self) -> bool {
        self.caps.output_streams > 0 && self.codec_mask != 0
    }
    pub fn version(&self) -> (u8, u8) {
        init::read_version(self)
    }
    #[inline]
    pub fn codec_count(&self) -> u32 {
        self.codec_mask.count_ones()
    }

    pub fn reset_stats(&self) {
        self.bytes_played.store(0, Ordering::Relaxed);
        self.bytes_recorded.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
        self.underruns.store(0, Ordering::Relaxed);
        self.overruns.store(0, Ordering::Relaxed);
    }
}
