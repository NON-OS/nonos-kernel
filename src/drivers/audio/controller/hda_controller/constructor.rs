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
use super::super::super::types::{AudioFormat, DmaRegion};
use super::super::init::{self, Capabilities};
use super::super::stream;
use super::structure::HdAudioController;
use crate::drivers::pci::{PciBar, PciDevice};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8};

impl HdAudioController {
    pub fn new(pci: &PciDevice) -> Result<Self, AudioError> {
        let bar = pci.get_bar(0).ok_or(AudioError::Bar0NotMmio)?;
        let base = match bar {
            PciBar::Memory { address, .. } => address.as_u64() as usize,
            _ => return Err(AudioError::Bar0NotMmio),
        };
        let corb = DmaRegion::new(CORB_SIZE)?;
        let rirb = DmaRegion::new(RIRB_SIZE)?;
        let bdl = DmaRegion::new(
            BDL_ENTRIES * core::mem::size_of::<super::super::super::types::BdlEntry>(),
        )?;
        let pcm_buf = DmaRegion::new(PCM_BUFFER_SIZE)?;
        let in_bdl = DmaRegion::new(
            BDL_ENTRIES * core::mem::size_of::<super::super::super::types::BdlEntry>(),
        )?;
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

    pub(super) fn init(&mut self) -> Result<(), AudioError> {
        let (caps, codec_mask, primary_codec, codec_paths) =
            init::init_controller(self, &self.corb, &self.rirb)?;
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

    pub(super) fn init_output_stream(&mut self) -> Result<(), AudioError> {
        stream::init_output_stream(self, self.out_stream, &self.bdl, &self.pcm_buf, &self.format)
    }

    pub(super) fn init_input_stream(&mut self) -> Result<(), AudioError> {
        stream::init_input_stream(
            self,
            self.in_stream,
            &self.in_bdl,
            &self.in_pcm_buf,
            &self.format,
        )
    }
}
