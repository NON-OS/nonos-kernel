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

//! HD Audio controller initialization.

use super::super::error::AudioError;
use super::super::types::DmaRegion;
use super::super::constants::*;
use super::helpers::{RegisterAccess, spin_until, spin_while};
use super::corb_rirb::{init_corb, init_rirb, stop_corb, stop_rirb};
use super::codec::{self, discover_codec, init_codec_path, apply_codec_quirks, CodecInfo, CodecPaths};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InitStage {
    NotStarted = 0,
    Resetting = 1,
    ReadingCapabilities = 2,
    InitBuffers = 3,
    DiscoveringCodecs = 4,
    ConfiguringPaths = 5,
    Ready = 6,
    Failed = 0xFF,
}

impl InitStage {
    pub fn name(&self) -> &'static str {
        match self {
            InitStage::NotStarted => "Not Started",
            InitStage::Resetting => "Resetting Controller",
            InitStage::ReadingCapabilities => "Reading Capabilities",
            InitStage::InitBuffers => "Initializing Buffers",
            InitStage::DiscoveringCodecs => "Discovering Codecs",
            InitStage::ConfiguringPaths => "Configuring Paths",
            InitStage::Ready => "Ready",
            InitStage::Failed => "Failed",
        }
    }

    pub fn is_ready(&self) -> bool {
        matches!(self, InitStage::Ready)
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, InitStage::Failed)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Capabilities {
    pub output_streams: u8,
    pub input_streams: u8,
    pub bidi_streams: u8,
    pub addr64: bool,
    pub nsdo: u8,
}

impl Capabilities {
    pub fn from_gcap(gcap: u16) -> Self {
        Self {
            output_streams: ((gcap >> 12) & 0xF) as u8,
            input_streams: ((gcap >> 8) & 0xF) as u8,
            bidi_streams: ((gcap >> 3) & 0x1F) as u8,
            addr64: (gcap & (1 << 0)) != 0,
            nsdo: ((gcap >> 1) & 0x3) as u8,
        }
    }

    pub fn total_streams(&self) -> u8 {
        self.output_streams + self.input_streams + self.bidi_streams
    }
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            output_streams: 0,
            input_streams: 0,
            bidi_streams: 0,
            addr64: false,
            nsdo: 0,
        }
    }
}

pub(super) fn reset_controller<T: RegisterAccess>(ctrl: &T) -> Result<(), AudioError> {
    let mut gctl = ctrl.read_reg32(GCTL);
    gctl &= !GCTL_CRST;
    ctrl.write_reg32(GCTL, gctl);

    if !spin_while(
        || (ctrl.read_reg32(GCTL) & GCTL_CRST) != 0,
        SPIN_TIMEOUT_DEFAULT,
    ) {
        return Err(AudioError::CrstClearTimeout);
    }

    for _ in 0..100 {
        core::hint::spin_loop();
    }

    let mut gctl = ctrl.read_reg32(GCTL);
    gctl |= GCTL_CRST;
    ctrl.write_reg32(GCTL, gctl);

    if !spin_until(
        || (ctrl.read_reg32(GCTL) & GCTL_CRST) != 0,
        SPIN_TIMEOUT_DEFAULT,
    ) {
        return Err(AudioError::CrstSetTimeout);
    }

    for _ in 0..1000 {
        core::hint::spin_loop();
    }

    Ok(())
}

pub(super) fn read_capabilities<T: RegisterAccess>(ctrl: &T) -> Capabilities {
    let gcap = ctrl.read_reg16(GCAP);
    Capabilities::from_gcap(gcap)
}

pub(super) fn read_codec_mask<T: RegisterAccess>(ctrl: &T) -> u16 {
    ctrl.read_reg16(STATESTS)
}

pub(super) fn find_primary_codec(codec_mask: u16) -> Option<u8> {
    (0..=15).find(|c| (codec_mask & (1 << c)) != 0).map(|c| c as u8)
}

pub(super) fn init_command_buffers<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
) {
    init_corb(ctrl, corb);
    init_rirb(ctrl, rirb);
}

pub(super) fn discover_codecs<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    codec_mask: u16,
) -> alloc::vec::Vec<CodecInfo> {
    let mut codecs = alloc::vec::Vec::new();

    for cad in 0..=15u8 {
        if (codec_mask & (1 << cad)) != 0 {
            match discover_codec(ctrl, corb, rirb, corb_entries, rirb_entries, cad) {
                Ok(info) => {
                    crate::log::logger::log_critical(&alloc::format!(
                        "HDA: Codec {} - {} {} (0x{:04X}:0x{:04X})",
                        cad,
                        info.vendor_name(),
                        info.device_name(),
                        info.vendor_id,
                        info.device_id
                    ));

                    if info.quirks.has_quirks() {
                        crate::log::logger::log_critical(&alloc::format!(
                            "HDA: Applying {} quirks for codec {}",
                            info.quirks.quirk_count(),
                            cad
                        ));
                        let _ = apply_codec_quirks(
                            ctrl, corb, rirb, corb_entries, rirb_entries, &info
                        );
                    }

                    match init_codec_path(ctrl, corb, rirb, corb_entries, rirb_entries, &info) {
                        Ok(_) => {}
                        Err(e) => {
                            crate::log::logger::log_critical(&alloc::format!(
                                "HDA: Path init failed for codec {}: {:?}",
                                cad, e
                            ));
                        }
                    }

                    codecs.push(info);
                }
                Err(e) => {
                    crate::log::logger::log_critical(&alloc::format!(
                        "HDA: Codec {} discovery failed: {:?}",
                        cad, e
                    ));
                }
            }
        }
    }

    codecs
}

pub(super) fn init_controller<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
) -> Result<(Capabilities, u16, Option<u8>, Option<CodecPaths>), AudioError> {
    reset_controller(ctrl)?;

    clear_codec_status(ctrl);

    let caps = read_capabilities(ctrl);
    crate::log::logger::log_critical(&alloc::format!(
        "HDA: {} output, {} input, {} bidi streams",
        caps.output_streams, caps.input_streams, caps.bidi_streams
    ));

    init_command_buffers(ctrl, corb, rirb);

    let codec_mask = read_codec_mask(ctrl);
    let primary_codec = find_primary_codec(codec_mask);

    let codecs = discover_codecs(
        ctrl, corb, rirb,
        CORB_ENTRIES, RIRB_ENTRIES,
        codec_mask,
    );

    let codec_paths = if let Some(cad) = primary_codec {
        let primary_codec_info = codecs.iter().find(|c| c.cad == cad);

        if let Some(codec_info) = primary_codec_info {
            match codec::discover_paths(
                ctrl, corb, rirb,
                CORB_ENTRIES, RIRB_ENTRIES, codec_info,
            ) {
                Ok(paths) => {
                    if paths.output_count > 0 {
                        if let Err(e) = codec::init_codec_path(
                            ctrl, corb, rirb,
                            CORB_ENTRIES, RIRB_ENTRIES,
                            codec_info,
                        ) {
                            crate::log::logger::log_critical(&alloc::format!(
                                "HDA: Failed to init codec path: {:?}", e
                            ));
                        }
                    }
                    Some(paths)
                }
                Err(e) => {
                    crate::log::logger::log_critical(&alloc::format!(
                        "HDA: Failed to discover paths: {:?}", e
                    ));
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    Ok((caps, codec_mask, primary_codec, codec_paths))
}

pub(super) fn disable_interrupts<T: RegisterAccess>(ctrl: &T) {
    let intctl = ctrl.read_reg32(INTCTL);
    ctrl.write_reg32(INTCTL, intctl & !((1 << 31) | (1 << 30)));
}

pub fn shutdown_controller<T: RegisterAccess>(ctrl: &T) -> Result<(), AudioError> {
    disable_interrupts(ctrl);

    stop_corb(ctrl);
    stop_rirb(ctrl);

    let mut gctl = ctrl.read_reg32(GCTL);
    gctl &= !GCTL_CRST;
    ctrl.write_reg32(GCTL, gctl);

    if !spin_while(
        || (ctrl.read_reg32(GCTL) & GCTL_CRST) != 0,
        SPIN_TIMEOUT_DEFAULT,
    ) {
        return Err(AudioError::CrstClearTimeout);
    }

    Ok(())
}

pub(super) fn clear_codec_status<T: RegisterAccess>(ctrl: &T) {
    ctrl.write_reg16(STATESTS, 0xFFFF);
}

pub fn is_in_reset<T: RegisterAccess>(ctrl: &T) -> bool {
    (ctrl.read_reg32(GCTL) & GCTL_CRST) == 0
}

pub fn is_running<T: RegisterAccess>(ctrl: &T) -> bool {
    (ctrl.read_reg32(GCTL) & GCTL_CRST) != 0
}

pub fn read_version<T: RegisterAccess>(ctrl: &T) -> (u8, u8) {
    let vmin = ctrl.read_reg8(VMIN);
    let vmaj = ctrl.read_reg8(VMAJ);
    (vmaj, vmin)
}

pub fn validate_controller<T: RegisterAccess>(ctrl: &T) -> Result<(), AudioError> {
    if is_in_reset(ctrl) {
        return Err(AudioError::CrstClearTimeout);
    }

    let caps = read_capabilities(ctrl);
    if caps.output_streams == 0 {
        return Err(AudioError::NoCodecPresent);
    }

    Ok(())
}
