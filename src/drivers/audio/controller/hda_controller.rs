// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
//! HD Audio Controller.

use core::ptr;
use core::sync::atomic::{AtomicU64, AtomicU8, AtomicBool, Ordering};
use crate::drivers::pci::{PciBar, PciDevice};
use super::super::error::AudioError;
use super::super::types::{DmaRegion, AudioStats, AudioFormat, Volume};
use super::super::constants::*;
use super::helpers::RegisterAccess;
use super::init::{self, Capabilities};
use super::codec::{self, CodecPaths};
use super::stream;

/// # Thread Safety
///
/// All mutable state is protected by atomic operations. The controller itself
/// is wrapped in a Mutex at the module level.
pub struct HdAudioController {
    /// MMIO base address
    base: usize,
    /// Controller capabilities
    caps: Capabilities,
    /// CORB DMA region
    corb: DmaRegion,
    /// RIRB DMA region
    rirb: DmaRegion,
    /// Number of CORB entries
    corb_entries: usize,
    /// Number of RIRB entries
    rirb_entries: usize,
    /// Codec presence mask (bit N = codec at address N present)
    codec_mask: u16,
    /// Primary codec address (first detected)
    primary_codec: Option<u8>,
    /// Codec audio paths for volume control
    codec_paths: Option<CodecPaths>,
    /// Output stream index (1-based)
    out_stream: u8,
    /// Buffer Descriptor List DMA region
    bdl: DmaRegion,
    /// PCM data buffer DMA region
    pcm_buf: DmaRegion,
    /// Current audio format
    format: AudioFormat,
    /// Current volume level (0-100)
    volume: AtomicU8,
    /// Mute state
    muted: AtomicBool,
    /// Statistics: bytes played
    bytes_played: AtomicU64,
    /// Statistics: error count
    errors: AtomicU64,
}

// SAFETY: HdAudioController is safe to send between threads.
// All mutable state is protected by atomic operations.
unsafe impl Send for HdAudioController {}
unsafe impl Sync for HdAudioController {}

impl RegisterAccess for HdAudioController {
    #[inline]
    fn base_addr(&self) -> usize {
        self.base
    }
}

impl HdAudioController {
    /// Creates and initializes a new HD Audio controller.
    pub fn new(pci: &PciDevice) -> Result<Self, AudioError> {
        let bar = pci.get_bar(0).map_err(|_| AudioError::Bar0NotMmio)?;
        let base = match bar {
            PciBar::Memory { address, .. } => address.as_u64() as usize,
            _ => return Err(AudioError::Bar0NotMmio),
        };

        let corb = DmaRegion::new(CORB_SIZE)?;
        let rirb = DmaRegion::new(RIRB_SIZE)?;
        let bdl = DmaRegion::new(BDL_ENTRIES * core::mem::size_of::<super::super::types::BdlEntry>())?;
        let pcm_buf = DmaRegion::new(PCM_BUFFER_SIZE)?;

        let mut controller = Self {
            base,
            caps: Capabilities::default(),
            corb,
            rirb,
            corb_entries: CORB_ENTRIES,
            rirb_entries: RIRB_ENTRIES,
            codec_mask: 0,
            primary_codec: None,
            codec_paths: None,
            out_stream: 1,
            bdl,
            pcm_buf,
            format: AudioFormat::default_format(),
            volume: AtomicU8::new(100),
            muted: AtomicBool::new(false),
            bytes_played: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        };

        controller.init()?;
        Ok(controller)
    }

    fn init(&mut self) -> Result<(), AudioError> {
        let (caps, codec_mask, primary_codec, codec_paths) = init::init_controller(
            self,
            &self.corb,
            &self.rirb,
        )?;

        self.caps = caps;
        self.codec_mask = codec_mask;
        self.primary_codec = primary_codec;
        self.codec_paths = codec_paths;
        self.init_output_stream()?;
        Ok(())
    }

    fn init_output_stream(&mut self) -> Result<(), AudioError> {
        stream::init_output_stream(self, self.out_stream, &self.bdl, &self.pcm_buf, &self.format)
    }

    /// Plays PCM audio data.
    pub fn play_pcm(&self, data: &[u8]) -> Result<(), AudioError> {
        let n = core::cmp::min(data.len(), self.pcm_buf.len());
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), self.pcm_buf.as_mut_ptr::<u8>(), n);
        }

        stream::start_stream(self, self.out_stream);

        if let Err(e) = stream::wait_playback_complete(self, self.out_stream) {
            self.errors.fetch_add(1, Ordering::Relaxed);
            stream::stop_stream(self, self.out_stream);
            return Err(e);
        }

        self.bytes_played.fetch_add(n as u64, Ordering::Relaxed);
        stream::stop_stream(self, self.out_stream);
        Ok(())
    }

    /// Returns controller statistics.
    pub fn get_stats(&self) -> AudioStats {
        let bytes = self.bytes_played.load(Ordering::Relaxed);
        let bytes_per_sample = self.format.bytes_per_sample() as u64;

        AudioStats {
            samples_played: if bytes_per_sample > 0 { bytes / bytes_per_sample } else { 0 },
            samples_recorded: 0,
            buffer_underruns: 0,
            buffer_overruns: 0,
            interrupts_handled: 0,
            active_streams: if stream::is_stream_running(self, self.out_stream) { 1 } else { 0 },
            codecs_detected: self.codec_mask.count_ones(),
            bytes_transferred: bytes,
            error_count: self.errors.load(Ordering::Relaxed),
        }
    }

    #[inline] pub fn output_streams(&self) -> u8 { self.caps.output_streams }
    #[inline] pub fn input_streams(&self) -> u8 { self.caps.input_streams }
    #[inline] pub fn codec_mask(&self) -> u16 { self.codec_mask }
    #[inline] pub fn primary_codec(&self) -> Option<u8> { self.primary_codec }
    #[inline] pub fn format(&self) -> AudioFormat { self.format }
    #[inline] pub fn buffer_size(&self) -> usize { self.pcm_buf.len() }
    #[inline] pub fn bytes_played(&self) -> u64 { self.bytes_played.load(Ordering::Relaxed) }
    #[inline] pub fn error_count(&self) -> u64 { self.errors.load(Ordering::Relaxed) }

    #[inline]
    pub fn get_volume(&self) -> Volume {
        Volume::new(self.volume.load(Ordering::Relaxed))
    }

    pub fn set_volume(&self, volume: u8) -> Result<(), AudioError> {
        let vol = volume.min(100);
        self.volume.store(vol, Ordering::Relaxed);

        if let (Some(cad), Some(ref paths)) = (self.primary_codec, &self.codec_paths) {
            codec::set_volume(
                self, &self.corb, &self.rirb,
                self.corb_entries, self.rirb_entries,
                cad, paths, vol,
            )?;
        }
        Ok(())
    }

    #[inline]
    pub fn is_muted(&self) -> bool {
        self.muted.load(Ordering::Relaxed)
    }

    pub fn set_mute(&self, mute: bool) -> Result<(), AudioError> {
        self.muted.store(mute, Ordering::Relaxed);

        if let (Some(cad), Some(ref paths)) = (self.primary_codec, &self.codec_paths) {
            codec::set_mute(
                self, &self.corb, &self.rirb,
                self.corb_entries, self.rirb_entries,
                cad, paths, mute,
            )?;
        }
        Ok(())
    }

    pub fn toggle_mute(&self) -> Result<bool, AudioError> {
        let new_muted = !self.muted.load(Ordering::Relaxed);
        self.set_mute(new_muted)?;
        Ok(new_muted)
    }

    #[inline] pub fn is_ready(&self) -> bool { self.caps.output_streams > 0 && self.codec_mask != 0 }
    #[inline] pub fn is_playing(&self) -> bool { stream::is_stream_running(self, self.out_stream) }
    #[inline] pub fn capabilities(&self) -> Capabilities { self.caps }
    pub fn version(&self) -> (u8, u8) { init::read_version(self) }
    #[inline] pub fn codec_count(&self) -> u32 { self.codec_mask.count_ones() }

    pub fn reset_stats(&self) {
        self.bytes_played.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
    }

    pub fn shutdown(&self) -> Result<(), AudioError> {
        if self.is_playing() {
            stream::stop_stream(self, self.out_stream);
        }
        init::shutdown_controller(self)
    }
}
