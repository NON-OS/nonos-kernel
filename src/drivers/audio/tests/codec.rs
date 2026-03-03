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

use super::super::controller::{
    compose_verb, device_name, vendor_name, AudioPath, Capabilities, CodecInfo, CodecPaths,
    CodecQuirks, WidgetInfo,
};

#[test]
fn test_compose_verb() {
    let verb = compose_verb(0, 0, 0xF00, 0x00);
    assert_eq!(verb, 0x000F_0000);

    let verb = compose_verb(1, 2, 0x705, 0x00);
    assert_eq!(verb, 0x1027_0500);
}

#[test]
fn test_capabilities_from_gcap() {
    let gcap = (4 << 12) | (2 << 8) | (1 << 3) | 1;
    let caps = Capabilities::from_gcap(gcap);

    assert_eq!(caps.output_streams, 4);
    assert_eq!(caps.input_streams, 2);
    assert_eq!(caps.bidi_streams, 1);
    assert!(caps.addr64);
    assert_eq!(caps.total_streams(), 7);
}

#[test]
fn test_vendor_name() {
    assert_eq!(vendor_name(0x8086), "Intel");
    assert_eq!(vendor_name(0x10DE), "NVIDIA");
    assert_eq!(vendor_name(0x1002), "AMD/ATI");
    assert_eq!(vendor_name(0x10EC), "Realtek");
    assert_eq!(vendor_name(0x14F1), "Conexant");
    assert_eq!(vendor_name(0x1106), "VIA");
    assert_eq!(vendor_name(0x1AF4), "VirtIO");
    assert_eq!(vendor_name(0x0000), "Unknown");
}

#[test]
fn test_codec_info_empty() {
    let codec = CodecInfo::empty();
    assert_eq!(codec.cad, 0);
    assert_eq!(codec.vendor_id, 0);
    assert_eq!(codec.device_id, 0);
    assert_eq!(codec.revision_id, 0);
    assert_eq!(codec.fn_group_start, 0);
    assert_eq!(codec.fn_group_count, 0);
}

#[test]
fn test_codec_info_copy() {
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
    assert_eq!(codec1.cad, codec2.cad);
    assert_eq!(codec1.vendor_id, codec2.vendor_id);
    assert_eq!(codec1.device_id, codec2.device_id);
}

#[test]
fn test_widget_info_default() {
    let widget = WidgetInfo::default();
    assert_eq!(widget.nid, 0);
    assert_eq!(widget.widget_type, 0);
    assert_eq!(widget.caps, 0);
    assert_eq!(widget.conn_len, 0);
}

#[test]
fn test_widget_info_has_out_amp() {
    let widget = WidgetInfo {
        caps: 1 << 2,
        ..Default::default()
    };
    assert!(widget.has_out_amp());

    let widget_no_amp = WidgetInfo::default();
    assert!(!widget_no_amp.has_out_amp());
}

#[test]
fn test_widget_info_has_in_amp() {
    let widget = WidgetInfo {
        caps: 1 << 1,
        ..Default::default()
    };
    assert!(widget.has_in_amp());

    let widget_no_amp = WidgetInfo::default();
    assert!(!widget_no_amp.has_in_amp());
}

#[test]
fn test_widget_info_is_output_pin() {
    let widget = WidgetInfo {
        widget_type: 4,
        pin_caps: 1 << 4,
        ..Default::default()
    };
    assert!(widget.is_output_pin());

    let dac = WidgetInfo {
        widget_type: 0,
        pin_caps: 1 << 4,
        ..Default::default()
    };
    assert!(!dac.is_output_pin());
}

#[test]
fn test_widget_info_is_input_pin() {
    let widget = WidgetInfo {
        widget_type: 4,
        pin_caps: 1 << 5,
        ..Default::default()
    };
    assert!(widget.is_input_pin());
}

#[test]
fn test_widget_info_pin_device_type() {
    let widget = WidgetInfo {
        pin_config: 0x1 << 20,
        ..Default::default()
    };
    assert_eq!(widget.pin_device_type(), 0x1);

    let hp_widget = WidgetInfo {
        pin_config: 0x2 << 20,
        ..Default::default()
    };
    assert_eq!(hp_widget.pin_device_type(), 0x2);
}

#[test]
fn test_widget_info_pin_connectivity() {
    let jack = WidgetInfo {
        pin_config: 0 << 30,
        ..Default::default()
    };
    assert_eq!(jack.pin_connectivity(), 0);

    let none = WidgetInfo {
        pin_config: 1 << 30,
        ..Default::default()
    };
    assert_eq!(none.pin_connectivity(), 1);
}

#[test]
fn test_widget_info_is_connected() {
    let connected = WidgetInfo {
        pin_config: 0 << 30,
        ..Default::default()
    };
    assert!(connected.is_connected());

    let not_connected = WidgetInfo {
        pin_config: 1 << 30,
        ..Default::default()
    };
    assert!(!not_connected.is_connected());
}

#[test]
fn test_widget_info_amp_steps() {
    let widget = WidgetInfo {
        amp_out_caps: 0x7F << 8,
        amp_in_caps: 0x40 << 8,
        ..Default::default()
    };
    assert_eq!(widget.out_amp_steps(), 127);
    assert_eq!(widget.in_amp_steps(), 64);
}

#[test]
fn test_audio_path_default() {
    let path = AudioPath::default();
    assert_eq!(path.dac_nid, 0);
    assert_eq!(path.path, [0; 8]);
    assert_eq!(path.path_len, 0);
    assert_eq!(path.pin_nid, 0);
    assert_eq!(path.device_type, 0);
    assert!(!path.active);
}

#[test]
fn test_audio_path_copy() {
    let path1 = AudioPath {
        dac_nid: 2,
        path: [5, 6, 0, 0, 0, 0, 0, 0],
        path_len: 2,
        pin_nid: 10,
        device_type: 1,
        active: true,
    };
    let path2 = path1;
    assert_eq!(path1.dac_nid, path2.dac_nid);
    assert_eq!(path1.pin_nid, path2.pin_nid);
    assert_eq!(path1.active, path2.active);
}

#[test]
fn test_codec_paths_default() {
    let paths = CodecPaths::default();
    assert_eq!(paths.output_count, 0);
    assert_eq!(paths.primary_output, 0);
    assert!(!paths.output_paths[0].active);
}

#[test]
fn test_device_name() {
    assert_eq!(device_name(0x10EC, 0x0892), "ALC892");
    assert_eq!(device_name(0x10EC, 0x0269), "ALC269");
    assert_eq!(device_name(0x10EC, 0x1220), "ALC1220");
    assert_eq!(device_name(0x8086, 0x2812), "Tigerlake HDMI");
    assert_eq!(device_name(0x8086, 0x2814), "Alderlake HDMI");
    assert_eq!(device_name(0x1002, 0xAB28), "Navi 21 HDMI");
    assert_eq!(device_name(0x1AF4, 0x0001), "VirtIO Sound");
    assert_eq!(device_name(0x1234, 0x5678), "Unknown Device");
}

#[test]
fn test_vendor_name_extended() {
    assert_eq!(vendor_name(0x11D4), "Analog Devices");
    assert_eq!(vendor_name(0x1013), "Cirrus Logic");
    assert_eq!(vendor_name(0x13F6), "C-Media");
    assert_eq!(vendor_name(0x15AD), "VMware");
    assert_eq!(vendor_name(0x19E5), "Huawei");
    assert_eq!(vendor_name(0x1D17), "Zhaoxin");
}
