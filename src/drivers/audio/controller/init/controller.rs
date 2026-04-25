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
use super::super::super::types::DmaRegion;
use super::super::codec::{self, CodecPaths};
use super::super::helpers::RegisterAccess;
use super::capabilities::{find_primary_codec, read_capabilities, read_codec_mask};
use super::discover::{discover_codecs, init_command_buffers};
use super::reset::reset_controller;
use super::types::Capabilities;

pub(crate) fn init_controller<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
) -> Result<(Capabilities, u16, Option<u8>, Option<CodecPaths>), AudioError> {
    reset_controller(ctrl)?;
    clear_codec_status(ctrl);
    let caps = read_capabilities(ctrl);
    crate::log::logger::log_critical(&alloc::format!(
        "HDA: {} out, {} in, {} bidi, 64bit={}, sdo={}",
        caps.output_streams,
        caps.input_streams,
        caps.bidi_streams,
        caps.addr64,
        caps.nsdo
    ));
    init_command_buffers(ctrl, corb, rirb);
    let codec_mask = read_codec_mask(ctrl);
    let primary_codec = find_primary_codec(codec_mask);
    let codecs = discover_codecs(ctrl, corb, rirb, CORB_ENTRIES, RIRB_ENTRIES, codec_mask);
    let codec_paths = if let Some(cad) = primary_codec {
        let primary_codec_info = codecs.iter().find(|c| c.cad == cad);
        if let Some(codec_info) = primary_codec_info {
            match codec::discover_paths(ctrl, corb, rirb, CORB_ENTRIES, RIRB_ENTRIES, codec_info) {
                Ok(paths) => {
                    if paths.output_count > 0 {
                        if let Err(e) = codec::init_codec_path(
                            ctrl,
                            corb,
                            rirb,
                            CORB_ENTRIES,
                            RIRB_ENTRIES,
                            codec_info,
                        ) {
                            crate::log::logger::log_critical(&alloc::format!(
                                "HDA: Failed to init codec path: {:?}",
                                e
                            ));
                        }
                    }
                    Some(paths)
                }
                Err(e) => {
                    crate::log::logger::log_critical(&alloc::format!(
                        "HDA: Failed to discover paths: {:?}",
                        e
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

use super::super::super::error::AudioError;

fn clear_codec_status<T: RegisterAccess>(ctrl: &T) {
    ctrl.write_reg16(STATESTS, 0xFFFF);
}

pub(crate) fn read_version<T: RegisterAccess>(ctrl: &T) -> (u8, u8) {
    let vmaj = ctrl.read_reg8(VMAJ);
    let vmin = ctrl.read_reg8(VMIN);
    (vmaj, vmin)
}

pub(crate) fn shutdown_controller<T: RegisterAccess>(ctrl: &T) -> Result<(), AudioError> {
    let mut gctl = ctrl.read_reg32(GCTL);
    gctl &= !GCTL_CRST;
    ctrl.write_reg32(GCTL, gctl);
    Ok(())
}
