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

//! HD Audio controller driver.

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

pub struct HdAudioController {
    base: usize,
    caps: Capabilities,
    corb: DmaRegion,
    rirb: DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    codec_mask: u16,
    primary_codec: Option<u8>,
    codec_paths: Option<CodecPaths>,
    out_stream: u8,
    in_stream: u8,
    bdl: DmaRegion,
    pcm_buf: DmaRegion,
    in_bdl: DmaRegion,
    in_pcm_buf: DmaRegion,
    format: AudioFormat,
    volume: AtomicU8,
    muted: AtomicBool,
    bytes_played: AtomicU64,
    bytes_recorded: AtomicU64,
    errors: AtomicU64,
    underruns: AtomicU64,
    overruns: AtomicU64,
    input_enabled: bool,
}

// SAFETY: all mutable state is protected by atomic operations
unsafe impl Send for HdAudioController {}
unsafe impl Sync for HdAudioController {}

impl RegisterAccess for HdAudioController {
    #[inline]
    fn base_addr(&self) -> usize {
        self.base
    }
}

impl HdAudioController {
    pub fn new(pci: &PciDevice) -> Result<Self, AudioError> {
        let bar = pci.get_bar(0).ok_or(AudioError::Bar0NotMmio)?;
        let base = match bar {
            PciBar::Memory { address, .. } => address.as_u64() as usize,
            _ => return Err(AudioError::Bar0NotMmio),
        };

        let corb = DmaRegion::new(CORB_SIZE)?;
        let rirb = DmaRegion::new(RIRB_SIZE)?;
        let bdl = DmaRegion::new(BDL_ENTRIES * core::mem::size_of::<super::super::types::BdlEntry>())?;
        let pcm_buf = DmaRegion::new(PCM_BUFFER_SIZE)?;
        let in_bdl = DmaRegion::new(BDL_ENTRIES * core::mem::size_of::<super::super::types::BdlEntry>())?;
        let in_pcm_buf = DmaRegion::new(PCM_BUFFER_SIZE)?;

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
            in_stream: 0,
            bdl,
            pcm_buf,
            in_bdl,
            in_pcm_buf,
            format: AudioFormat::default_format(),
            volume: AtomicU8::new(100),
            muted: AtomicBool::new(false),
            bytes_played: AtomicU64::new(0),
            bytes_recorded: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            underruns: AtomicU64::new(0),
            overruns: AtomicU64::new(0),
            input_enabled: false,
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

        if self.caps.input_streams > 0 {
            if self.init_input_stream().is_ok() {
                self.input_enabled = true;
            }
        }

        Ok(())
    }

    fn init_output_stream(&mut self) -> Result<(), AudioError> {
        stream::init_output_stream(self, self.out_stream, &self.bdl, &self.pcm_buf, &self.format)
    }

    fn init_input_stream(&mut self) -> Result<(), AudioError> {
        stream::init_input_stream(self, self.in_stream, &self.in_bdl, &self.in_pcm_buf, &self.format)
    }

    pub fn play_pcm(&self, data: &[u8]) -> Result<(), AudioError> {
        let n = core::cmp::min(data.len(), self.pcm_buf.len());
        // SAFETY: pcm_buf is valid DMA region, copying at most pcm_buf.len() bytes
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

    fn check_stream_errors(&self, stream_index: u8) {
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
        // SAFETY: in_pcm_buf is valid DMA region, copying at most in_pcm_buf.len() bytes
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

    pub fn get_stats(&self) -> AudioStats {
        let bytes = self.bytes_played.load(Ordering::Relaxed);
        let recorded = self.bytes_recorded.load(Ordering::Relaxed);
        let bytes_per_sample = self.format.bytes_per_sample() as u64;

        let mut active = 0u64;
        if stream::is_stream_running(self, self.out_stream) { active += 1; }
        if self.input_enabled && stream::is_stream_running(self, self.in_stream) { active += 1; }

        AudioStats {
            samples_played: if bytes_per_sample > 0 { bytes / bytes_per_sample } else { 0 },
            samples_recorded: if bytes_per_sample > 0 { recorded / bytes_per_sample } else { 0 },
            buffer_underruns: self.underruns.load(Ordering::Relaxed),
            buffer_overruns: self.overruns.load(Ordering::Relaxed),
            interrupts_handled: 0,
            active_streams: active,
            codecs_detected: self.codec_mask.count_ones(),
            bytes_transferred: bytes + recorded,
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
        self.bytes_recorded.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
        self.underruns.store(0, Ordering::Relaxed);
        self.overruns.store(0, Ordering::Relaxed);
    }

    pub fn shutdown(&self) -> Result<(), AudioError> {
        if self.is_playing() {
            stream::stop_stream(self, self.out_stream);
        }
        init::shutdown_controller(self)
    }
}
