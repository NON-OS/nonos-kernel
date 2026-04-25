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

use super::super::super::corb_rirb::get_parameter;
use super::super::super::helpers::RegisterAccess;
use super::super::quirks::get_codec_quirks;
use super::super::stats::{increment_codecs_discovered, increment_quirks_applied};
use super::super::types::CodecInfo;
use crate::drivers::audio::constants::{PARAM_REVISION_ID, PARAM_SUB_NODE_COUNT, PARAM_VENDOR_ID};
use crate::drivers::audio::error::AudioError;
use crate::drivers::audio::types::DmaRegion;

pub(crate) fn discover_codec<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
) -> Result<CodecInfo, AudioError> {
    let vendor_device =
        get_parameter(ctrl, corb, rirb, corb_entries, rirb_entries, cad, 0, PARAM_VENDOR_ID)?;
    let vendor_id = (vendor_device >> 16) as u16;
    let device_id = (vendor_device & 0xFFFF) as u16;
    if vendor_id == 0x0000 || vendor_id == 0xFFFF {
        return Err(AudioError::NoCodecPresent);
    }
    let revision_id =
        get_parameter(ctrl, corb, rirb, corb_entries, rirb_entries, cad, 0, PARAM_REVISION_ID)
            .unwrap_or(0);
    let sub_nodes =
        get_parameter(ctrl, corb, rirb, corb_entries, rirb_entries, cad, 0, PARAM_SUB_NODE_COUNT)
            .unwrap_or(0);
    let fn_group_start = ((sub_nodes >> 16) & 0xFF) as u8;
    let fn_group_count = (sub_nodes & 0xFF) as u8;
    let quirks = get_codec_quirks(vendor_id, device_id);
    increment_codecs_discovered();
    if quirks.has_quirks() {
        increment_quirks_applied();
    }
    Ok(CodecInfo { cad, vendor_id, device_id, revision_id, fn_group_start, fn_group_count, quirks })
}
