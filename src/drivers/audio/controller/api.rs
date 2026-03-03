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

use super::codec::{
    self, AudioPath, CodecInfo, CodecQuirks, WidgetInfo,
};

pub fn get_codec_details(codec_id: u32) -> (CodecInfo, CodecQuirks) {
    let vendor_id = (codec_id >> 16) as u16;
    let device_id = (codec_id & 0xFFFF) as u16;
    let quirks = codec::get_codec_quirks(vendor_id, device_id);
    let info = CodecInfo {
        cad: 0,
        vendor_id,
        device_id,
        revision_id: 0,
        fn_group_start: 0,
        fn_group_count: 0,
        quirks,
    };
    (info, quirks)
}

pub fn codec_statistics() -> (u32, u32, u32) {
    codec::codec_stats()
}

pub fn describe_widget(widget_type: u8) -> &'static str {
    codec::widget_type_name(widget_type)
}

pub fn describe_pin_device(device_type: u8) -> &'static str {
    codec::pin_device_type_name(device_type)
}

pub fn find_audio_paths(widgets: &[WidgetInfo]) -> Option<AudioPath> {
    if widgets.is_empty() {
        return None;
    }
    Some(AudioPath {
        dac_nid: 0,
        path: [0u8; 8],
        path_len: 0,
        pin_nid: 0,
        device_type: 0,
        active: false,
    })
}

pub fn get_codec_vendor_name(vendor_id: u16) -> &'static str {
    codec::vendor_name(vendor_id)
}

pub fn get_codec_device_name(vendor_id: u16, device_id: u16) -> &'static str {
    codec::device_name(vendor_id, device_id)
}
