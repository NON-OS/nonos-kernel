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

use super::constants::*;

pub fn vendor_name(vendor_id: u16) -> &'static str {
    match vendor_id {
        0x8086 => "Intel",
        0x10DE => "NVIDIA",
        0x1002 => "AMD/ATI",
        0x10EC => "Realtek",
        0x14F1 => "Conexant",
        0x1106 => "VIA",
        0x11D4 => "Analog Devices",
        0x1057 => "Motorola",
        0x1095 => "Silicon Image",
        0x17E8 => "Chrontel",
        0x1AF4 => "VirtIO",
        0x1013 => "Cirrus Logic",
        0x1039 => "SiS",
        0x10B9 => "ALi",
        0x1274 => "Creative/Ensoniq",
        0x13F6 => "C-Media",
        0x15AD => "VMware",
        0x19E5 => "Huawei",
        0x1D17 => "Zhaoxin",
        _ => "Unknown",
    }
}

pub fn device_name(vendor_id: u16, device_id: u16) -> &'static str {
    match (vendor_id, device_id) {
        (0x10EC, 0x0221) => "ALC221",
        (0x10EC, 0x0233) => "ALC233",
        (0x10EC, 0x0235) => "ALC235",
        (0x10EC, 0x0255) => "ALC255",
        (0x10EC, 0x0256) => "ALC256",
        (0x10EC, 0x0257) => "ALC257",
        (0x10EC, 0x0269) => "ALC269",
        (0x10EC, 0x0275) => "ALC275",
        (0x10EC, 0x0280) => "ALC280",
        (0x10EC, 0x0282) => "ALC282",
        (0x10EC, 0x0283) => "ALC283",
        (0x10EC, 0x0285) => "ALC285",
        (0x10EC, 0x0287) => "ALC287",
        (0x10EC, 0x0289) => "ALC289",
        (0x10EC, 0x0292) => "ALC292",
        (0x10EC, 0x0293) => "ALC293",
        (0x10EC, 0x0295) => "ALC295",
        (0x10EC, 0x0298) => "ALC298",
        (0x10EC, 0x0299) => "ALC299",
        (0x10EC, 0x0662) => "ALC662",
        (0x10EC, 0x0663) => "ALC663",
        (0x10EC, 0x0668) => "ALC668",
        (0x10EC, 0x0670) => "ALC670",
        (0x10EC, 0x0671) => "ALC671",
        (0x10EC, 0x0700) => "ALC700",
        (0x10EC, 0x0867) => "ALC867",
        (0x10EC, 0x0880) => "ALC880",
        (0x10EC, 0x0882) => "ALC882",
        (0x10EC, 0x0883) => "ALC883",
        (0x10EC, 0x0885) => "ALC885",
        (0x10EC, 0x0887) => "ALC887",
        (0x10EC, 0x0888) => "ALC888",
        (0x10EC, 0x0889) => "ALC889",
        (0x10EC, 0x0892) => "ALC892",
        (0x10EC, 0x0897) => "ALC897",
        (0x10EC, 0x0899) => "ALC899",
        (0x10EC, 0x0900) => "ALC1150",
        (0x10EC, 0x1168) => "ALC1168",
        (0x10EC, 0x1220) => "ALC1220",
        (0x8086, 0x2805) => "Haswell HDMI",
        (0x8086, 0x2807) => "Haswell HDMI",
        (0x8086, 0x2808) => "Broadwell HDMI",
        (0x8086, 0x2809) => "Skylake HDMI",
        (0x8086, 0x280A) => "Broxton HDMI",
        (0x8086, 0x280B) => "Kabylake HDMI",
        (0x8086, 0x280C) => "Cannonlake HDMI",
        (0x8086, 0x280D) => "Geminilake HDMI",
        (0x8086, 0x280F) => "Icelake HDMI",
        (0x8086, 0x2812) => "Tigerlake HDMI",
        (0x8086, 0x2814) => "Alderlake HDMI",
        (0x8086, 0x2815) => "Alderlake-P HDMI",
        (0x8086, 0x2816) => "Alderlake-N HDMI",
        (0x8086, 0x2819) => "Raptorlake HDMI",
        (0x8086, 0x281A) => "Raptorlake-P HDMI",
        (0x10DE, 0x0002..=0x000D) => "GeForce HDMI",
        (0x10DE, 0x0010) => "Tesla HDMI",
        (0x10DE, 0x0011) => "Quadro HDMI",
        (0x10DE, 0x0014) => "GTX 1060 HDMI",
        (0x10DE, 0x0015) => "GTX 1080 HDMI",
        (0x1002, 0x1308) | (0x1002, 0x1314) => "Kaveri HDMI",
        (0x1002, 0x4383) => "SBx00 HDMI",
        (0x1002, 0xAA01) => "R600 HDMI",
        (0x1002, 0xAA28) => "RV700 HDMI",
        (0x1002, 0xAA38) => "RV710/730 HDMI",
        (0x1002, 0xAA60) => "Redwood HDMI",
        (0x1002, 0xAA68) => "Cedar HDMI",
        (0x1002, 0xAA98) => "Caicos HDMI",
        (0x1002, 0xAAA0) => "Tahiti HDMI",
        (0x1002, 0xAAB0) => "Oland HDMI",
        (0x1002, 0xAAB8) => "Hawaii HDMI",
        (0x1002, 0xAAC0) => "Tonga HDMI",
        (0x1002, 0xAAC8) => "Fiji HDMI",
        (0x1002, 0xAAE0) => "Polaris 11 HDMI",
        (0x1002, 0xAAE8) => "Polaris 10 HDMI",
        (0x1002, 0xAAF0) => "Vega 10 HDMI",
        (0x1002, 0xAAF8) => "Vega 20 HDMI",
        (0x1002, 0xAB08) => "Navi 10 HDMI",
        (0x1002, 0xAB18) => "Navi 14 HDMI",
        (0x1002, 0xAB28) => "Navi 21 HDMI",
        (0x1002, 0xAB38) => "Navi 22 HDMI",
        (0x1AF4, _) => "VirtIO Sound",
        (0x15AD, _) => "VMware HD Audio",
        _ => "Unknown Device",
    }
}

pub fn widget_type_name(widget_type: u8) -> &'static str {
    match widget_type {
        WIDGET_TYPE_DAC => "DAC",
        WIDGET_TYPE_ADC => "ADC",
        WIDGET_TYPE_MIXER => "Mixer",
        WIDGET_TYPE_SELECTOR => "Selector",
        WIDGET_TYPE_PIN => "Pin",
        WIDGET_TYPE_POWER => "Power",
        WIDGET_TYPE_VOLUME_KNOB => "Volume",
        WIDGET_TYPE_BEEP => "Beep",
        _ => "Unknown",
    }
}

pub fn pin_device_type_name(device_type: u8) -> &'static str {
    match device_type {
        PIN_DEV_LINE_OUT => "Line Out",
        PIN_DEV_SPEAKER => "Speaker",
        PIN_DEV_HP_OUT => "Headphone",
        PIN_DEV_CD => "CD",
        PIN_DEV_SPDIF_OUT => "SPDIF Out",
        PIN_DEV_DIG_OTHER_OUT => "Digital Out",
        PIN_DEV_MODEM_LINE => "Modem Line",
        PIN_DEV_MODEM_HANDSET => "Modem Handset",
        PIN_DEV_LINE_IN => "Line In",
        PIN_DEV_AUX => "Aux",
        PIN_DEV_MIC_IN => "Mic In",
        PIN_DEV_TELEPHONY => "Telephony",
        PIN_DEV_SPDIF_IN => "SPDIF In",
        PIN_DEV_DIG_OTHER_IN => "Digital In",
        PIN_DEV_OTHER => "Other",
        _ => "Unknown",
    }
}
