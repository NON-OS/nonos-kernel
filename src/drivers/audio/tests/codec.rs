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

use crate::drivers::audio::controller::codec::{
    device_name, vendor_name, AudioPath, CodecInfo, CodecPaths, CodecQuirks, WidgetInfo,
};
use crate::drivers::audio::controller::compose_verb;
use crate::drivers::audio::controller::init::Capabilities;
use crate::test::framework::TestResult;

pub(crate) fn test_compose_verb() -> TestResult {
    let verb = compose_verb(0, 0, 0xF00, 0x00);
    if verb != 0x000F_0000 {
        return TestResult::Fail;
    }

    let verb = compose_verb(1, 2, 0x705, 0x00);
    if verb != 0x1027_0500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capabilities_from_gcap() -> TestResult {
    let gcap = (4 << 12) | (2 << 8) | (1 << 3) | 1;
    let caps = Capabilities::from_gcap(gcap);

    if caps.output_streams != 4 {
        return TestResult::Fail;
    }
    if caps.input_streams != 2 {
        return TestResult::Fail;
    }
    if caps.bidi_streams != 1 {
        return TestResult::Fail;
    }
    if !caps.addr64 {
        return TestResult::Fail;
    }
    if caps.total_streams() != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vendor_name() -> TestResult {
    if vendor_name(0x8086) != "Intel" {
        return TestResult::Fail;
    }
    if vendor_name(0x10DE) != "NVIDIA" {
        return TestResult::Fail;
    }
    if vendor_name(0x1002) != "AMD/ATI" {
        return TestResult::Fail;
    }
    if vendor_name(0x10EC) != "Realtek" {
        return TestResult::Fail;
    }
    if vendor_name(0x14F1) != "Conexant" {
        return TestResult::Fail;
    }
    if vendor_name(0x1106) != "VIA" {
        return TestResult::Fail;
    }
    if vendor_name(0x1AF4) != "VirtIO" {
        return TestResult::Fail;
    }
    if vendor_name(0x0000) != "Unknown" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_codec_info_empty() -> TestResult {
    let codec = CodecInfo::empty();
    if codec.cad != 0 {
        return TestResult::Fail;
    }
    if codec.vendor_id != 0 {
        return TestResult::Fail;
    }
    if codec.device_id != 0 {
        return TestResult::Fail;
    }
    if codec.revision_id != 0 {
        return TestResult::Fail;
    }
    if codec.fn_group_start != 0 {
        return TestResult::Fail;
    }
    if codec.fn_group_count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_codec_info_copy() -> TestResult {
    let codec1 = CodecInfo {
        cad: 1,
        vendor_id: 0x10EC,
        device_id: 0x0892,
        revision_id: 0x100302,
        fn_group_start: 1,
        fn_group_count: 1,
        quirks: CodecQuirks::default(),
    };
    let codec2 = codec1;
    if codec1.cad != codec2.cad {
        return TestResult::Fail;
    }
    if codec1.vendor_id != codec2.vendor_id {
        return TestResult::Fail;
    }
    if codec1.device_id != codec2.device_id {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_widget_info_default() -> TestResult {
    let widget = WidgetInfo::default();
    if widget.nid != 0 {
        return TestResult::Fail;
    }
    if widget.widget_type != 0 {
        return TestResult::Fail;
    }
    if widget.caps != 0 {
        return TestResult::Fail;
    }
    if widget.conn_len != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_widget_info_has_out_amp() -> TestResult {
    let widget = WidgetInfo { caps: 1 << 2, ..Default::default() };
    if !widget.has_out_amp() {
        return TestResult::Fail;
    }

    let widget_no_amp = WidgetInfo::default();
    if widget_no_amp.has_out_amp() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_widget_info_has_in_amp() -> TestResult {
    let widget = WidgetInfo { caps: 1 << 1, ..Default::default() };
    if !widget.has_in_amp() {
        return TestResult::Fail;
    }

    let widget_no_amp = WidgetInfo::default();
    if widget_no_amp.has_in_amp() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_widget_info_is_output_pin() -> TestResult {
    let widget = WidgetInfo { widget_type: 4, pin_caps: 1 << 4, ..Default::default() };
    if !widget.is_output_pin() {
        return TestResult::Fail;
    }

    let dac = WidgetInfo { widget_type: 0, pin_caps: 1 << 4, ..Default::default() };
    if dac.is_output_pin() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_widget_info_is_input_pin() -> TestResult {
    let widget = WidgetInfo { widget_type: 4, pin_caps: 1 << 5, ..Default::default() };
    if !widget.is_input_pin() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_widget_info_pin_device_type() -> TestResult {
    let widget = WidgetInfo { pin_config: 0x1 << 20, ..Default::default() };
    if widget.pin_device_type() != 0x1 {
        return TestResult::Fail;
    }

    let hp_widget = WidgetInfo { pin_config: 0x2 << 20, ..Default::default() };
    if hp_widget.pin_device_type() != 0x2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_widget_info_pin_connectivity() -> TestResult {
    let jack = WidgetInfo { pin_config: 0 << 30, ..Default::default() };
    if jack.pin_connectivity() != 0 {
        return TestResult::Fail;
    }

    let none = WidgetInfo { pin_config: 1 << 30, ..Default::default() };
    if none.pin_connectivity() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_widget_info_is_connected() -> TestResult {
    let connected = WidgetInfo { pin_config: 0 << 30, ..Default::default() };
    if !connected.is_connected() {
        return TestResult::Fail;
    }

    let not_connected = WidgetInfo { pin_config: 1 << 30, ..Default::default() };
    if not_connected.is_connected() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_widget_info_amp_steps() -> TestResult {
    let widget =
        WidgetInfo { amp_out_caps: 0x7F << 8, amp_in_caps: 0x40 << 8, ..Default::default() };
    if widget.out_amp_steps() != 127 {
        return TestResult::Fail;
    }
    if widget.in_amp_steps() != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audio_path_default() -> TestResult {
    let path = AudioPath::default();
    if path.dac_nid != 0 {
        return TestResult::Fail;
    }
    if path.path != [0; 8] {
        return TestResult::Fail;
    }
    if path.path_len != 0 {
        return TestResult::Fail;
    }
    if path.pin_nid != 0 {
        return TestResult::Fail;
    }
    if path.device_type != 0 {
        return TestResult::Fail;
    }
    if path.active {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audio_path_copy() -> TestResult {
    let path1 = AudioPath {
        dac_nid: 2,
        path: [5, 6, 0, 0, 0, 0, 0, 0],
        path_len: 2,
        pin_nid: 10,
        device_type: 1,
        active: true,
    };
    let path2 = path1;
    if path1.dac_nid != path2.dac_nid {
        return TestResult::Fail;
    }
    if path1.pin_nid != path2.pin_nid {
        return TestResult::Fail;
    }
    if path1.active != path2.active {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_codec_paths_default() -> TestResult {
    let paths = CodecPaths::default();
    if paths.output_count != 0 {
        return TestResult::Fail;
    }
    if paths.primary_output != 0 {
        return TestResult::Fail;
    }
    if paths.output_paths[0].active {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_name() -> TestResult {
    if device_name(0x10EC, 0x0892) != "ALC892" {
        return TestResult::Fail;
    }
    if device_name(0x10EC, 0x0269) != "ALC269" {
        return TestResult::Fail;
    }
    if device_name(0x10EC, 0x1220) != "ALC1220" {
        return TestResult::Fail;
    }
    if device_name(0x8086, 0x2812) != "Tigerlake HDMI" {
        return TestResult::Fail;
    }
    if device_name(0x8086, 0x2814) != "Alderlake HDMI" {
        return TestResult::Fail;
    }
    if device_name(0x1002, 0xAB28) != "Navi 21 HDMI" {
        return TestResult::Fail;
    }
    if device_name(0x1AF4, 0x0001) != "VirtIO Sound" {
        return TestResult::Fail;
    }
    if device_name(0x1234, 0x5678) != "Unknown Device" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vendor_name_extended() -> TestResult {
    if vendor_name(0x11D4) != "Analog Devices" {
        return TestResult::Fail;
    }
    if vendor_name(0x1013) != "Cirrus Logic" {
        return TestResult::Fail;
    }
    if vendor_name(0x13F6) != "C-Media" {
        return TestResult::Fail;
    }
    if vendor_name(0x15AD) != "VMware" {
        return TestResult::Fail;
    }
    if vendor_name(0x19E5) != "Huawei" {
        return TestResult::Fail;
    }
    if vendor_name(0x1D17) != "Zhaoxin" {
        return TestResult::Fail;
    }
    TestResult::Pass
}
