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

use super::super::super::types::DmaRegion;
use super::super::codec::{apply_codec_quirks, discover_codec, init_codec_path, CodecInfo};
use super::super::corb_rirb::{init_corb, init_rirb};
use super::super::helpers::RegisterAccess;

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
                        let _ =
                            apply_codec_quirks(ctrl, corb, rirb, corb_entries, rirb_entries, &info);
                    }
                    match init_codec_path(ctrl, corb, rirb, corb_entries, rirb_entries, &info) {
                        Ok(_) => {}
                        Err(e) => {
                            crate::log::logger::log_critical(&alloc::format!(
                                "HDA: Path init failed for codec {}: {:?}",
                                cad,
                                e
                            ));
                        }
                    }
                    codecs.push(info);
                }
                Err(e) => {
                    crate::log::logger::log_critical(&alloc::format!(
                        "HDA: Codec {} discovery failed: {:?}",
                        cad,
                        e
                    ));
                }
            }
        }
    }
    codecs
}
