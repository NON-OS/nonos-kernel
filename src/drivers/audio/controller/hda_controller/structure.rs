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

use super::super::super::types::{AudioFormat, DmaRegion};
use super::super::codec::CodecPaths;
use super::super::helpers::RegisterAccess;
use super::super::init::Capabilities;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8};

pub struct HdAudioController {
    pub(super) base: usize,
    pub(super) caps: Capabilities,
    pub(super) corb: DmaRegion,
    pub(super) rirb: DmaRegion,
    pub(super) corb_entries: usize,
    pub(super) rirb_entries: usize,
    pub(super) codec_mask: u16,
    pub(super) primary_codec: Option<u8>,
    pub(super) codec_paths: Option<CodecPaths>,
    pub(super) out_stream: u8,
    pub(super) in_stream: u8,
    pub(super) bdl: DmaRegion,
    pub(super) pcm_buf: DmaRegion,
    pub(super) in_bdl: DmaRegion,
    pub(super) in_pcm_buf: DmaRegion,
    pub(super) format: AudioFormat,
    pub(super) volume: AtomicU8,
    pub(super) muted: AtomicBool,
    pub(super) bytes_played: AtomicU64,
    pub(super) bytes_recorded: AtomicU64,
    pub(super) errors: AtomicU64,
    pub(super) underruns: AtomicU64,
    pub(super) overruns: AtomicU64,
    pub(super) input_enabled: bool,
}

unsafe impl Send for HdAudioController {}
unsafe impl Sync for HdAudioController {}

impl RegisterAccess for HdAudioController {
    #[inline]
    fn base_addr(&self) -> usize {
        self.base
    }
}
