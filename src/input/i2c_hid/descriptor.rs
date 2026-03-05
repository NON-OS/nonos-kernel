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

use alloc::vec::Vec;
use super::protocol::{
    HID_USAGE_PAGE_DIGITIZER, HID_USAGE_PAGE_GENERIC_DESKTOP, HID_USAGE_PAGE_BUTTON,
    HID_USAGE_TOUCHPAD, HID_USAGE_TOUCH_SCREEN, HID_USAGE_MOUSE, HID_USAGE_KEYBOARD,
    HID_USAGE_TIP_SWITCH, HID_USAGE_CONTACT_ID, HID_USAGE_X, HID_USAGE_Y,
    HID_USAGE_CONTACT_COUNT, HID_USAGE_BUTTON_PRIMARY, HID_USAGE_BUTTON_SECONDARY,
};

#[derive(Debug, Clone)]
pub struct HidDescriptor {
    pub hid_descriptor_length: u16,
    pub bcd_version: u16,
    pub report_descriptor_length: u16,
    pub report_descriptor_register: u16,
    pub input_register: u16,
    pub max_input_length: u16,
    pub output_register: u16,
    pub max_output_length: u16,
    pub command_register: u16,
    pub data_register: u16,
    pub vendor_id: u16,
    pub product_id: u16,
    pub version_id: u16,
}

impl HidDescriptor {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 30 {
            return None;
        }

        let hid_descriptor_length = u16::from_le_bytes([data[0], data[1]]);
        if hid_descriptor_length < 30 {
            return None;
        }

        let bcd_version = u16::from_le_bytes([data[2], data[3]]);
        if bcd_version != 0x0100 {
            return None;
        }

        Some(Self {
            hid_descriptor_length,
            bcd_version,
            report_descriptor_length: u16::from_le_bytes([data[4], data[5]]),
            report_descriptor_register: u16::from_le_bytes([data[6], data[7]]),
            input_register: u16::from_le_bytes([data[8], data[9]]),
            max_input_length: u16::from_le_bytes([data[10], data[11]]),
            output_register: u16::from_le_bytes([data[12], data[13]]),
            max_output_length: u16::from_le_bytes([data[14], data[15]]),
            command_register: u16::from_le_bytes([data[16], data[17]]),
            data_register: u16::from_le_bytes([data[18], data[19]]),
            vendor_id: u16::from_le_bytes([data[20], data[21]]),
            product_id: u16::from_le_bytes([data[22], data[23]]),
            version_id: u16::from_le_bytes([data[24], data[25]]),
        })
    }
}

impl Default for HidDescriptor {
    fn default() -> Self {
        Self {
            hid_descriptor_length: 30,
            bcd_version: 0x0100,
            report_descriptor_length: 0,
            report_descriptor_register: 0x0002,
            input_register: 0x0003,
            max_input_length: 64,
            output_register: 0x0004,
            max_output_length: 64,
            command_register: 0x0005,
            data_register: 0x0006,
            vendor_id: 0,
            product_id: 0,
            version_id: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FieldLocation {
    pub bit_offset: u16,
    pub bit_size: u16,
}

impl FieldLocation {
    pub fn is_valid(&self) -> bool {
        self.bit_size > 0
    }

    pub fn extract(&self, data: &[u8]) -> i32 {
        if !self.is_valid() || data.is_empty() {
            return 0;
        }

        let byte_offset = (self.bit_offset / 8) as usize;
        let bit_in_byte = (self.bit_offset % 8) as u32;

        if byte_offset >= data.len() {
            return 0;
        }

        match self.bit_size {
            1 => {
                ((data[byte_offset] >> bit_in_byte) & 1) as i32
            }
            8 if bit_in_byte == 0 => {
                data[byte_offset] as i32
            }
            16 if bit_in_byte == 0 && byte_offset + 1 < data.len() => {
                u16::from_le_bytes([data[byte_offset], data[byte_offset + 1]]) as i32
            }
            _ => {
                let mut value: u32 = 0;
                let mut bits_remaining = self.bit_size as u32;
                let mut current_bit = self.bit_offset as u32;

                while bits_remaining > 0 {
                    let byte_idx = (current_bit / 8) as usize;
                    if byte_idx >= data.len() {
                        break;
                    }

                    let bit_idx = current_bit % 8;
                    let bits_in_byte = (8 - bit_idx).min(bits_remaining);
                    let mask = ((1u32 << bits_in_byte) - 1) as u8;
                    let byte_val = (data[byte_idx] >> bit_idx) & mask;

                    let shift = self.bit_size as u32 - bits_remaining;
                    value |= (byte_val as u32) << shift;

                    bits_remaining -= bits_in_byte;
                    current_bit += bits_in_byte;
                }

                value as i32
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ContactFields {
    pub tip_switch: FieldLocation,
    pub confidence: FieldLocation,
    pub contact_id: FieldLocation,
    pub x: FieldLocation,
    pub y: FieldLocation,
    pub pressure: FieldLocation,
    pub width: FieldLocation,
    pub height: FieldLocation,
}

#[derive(Debug, Clone, Default)]
pub struct TouchpadLayout {
    pub report_id: u8,
    pub scan_time: FieldLocation,
    pub contact_count: FieldLocation,
    pub button: FieldLocation,
    pub contacts: [ContactFields; 5],
    pub contact_field_size: u16,  // Bits per contact
    pub total_report_size: u16,   // Total bits in report
}

#[derive(Debug, Clone)]
pub struct ReportInfo {
    pub report_id: u8,
    pub size: u16,
}

#[derive(Debug, Clone)]
pub struct ReportDescriptor {
    pub data: Vec<u8>,
    pub input_reports: Vec<ReportInfo>,
    pub output_reports: Vec<ReportInfo>,
    pub feature_reports: Vec<ReportInfo>,
    pub has_touchpad: bool,
    pub has_mouse: bool,
    pub has_keyboard: bool,
    pub max_contact_count: u8,
    pub has_x: bool,
    pub has_y: bool,
    pub has_tip: bool,
    pub has_contact_id: bool,
    pub logical_min_x: i32,
    pub logical_min_y: i32,
    pub logical_max_x: i32,
    pub logical_max_y: i32,
    pub physical_max_x: i32,
    pub physical_max_y: i32,
    pub touchpad_layout: TouchpadLayout,
}

impl ReportDescriptor {
    pub fn parse(data: &[u8]) -> Self {
        let mut desc = Self {
            data: data.to_vec(),
            input_reports: Vec::new(),
            output_reports: Vec::new(),
            feature_reports: Vec::new(),
            has_touchpad: false,
            has_mouse: false,
            has_keyboard: false,
            max_contact_count: 5,
            has_x: false,
            has_y: false,
            has_tip: false,
            has_contact_id: false,
            logical_min_x: 0,
            logical_min_y: 0,
            logical_max_x: 4096,
            logical_max_y: 4096,
            physical_max_x: 100,
            physical_max_y: 100,
            touchpad_layout: TouchpadLayout::default(),
        };

        desc.parse_items(data);
        desc
    }

    fn parse_items(&mut self, data: &[u8]) {
        let mut i = 0;
        let mut usage_page: u32 = 0;
        let mut usage: u32 = 0;
        let mut report_size: u32 = 0;
        let mut report_count: u32 = 0;
        let mut report_id: u8 = 0;
        let mut logical_min: i32 = 0;
        let mut logical_max: i32 = 0;
        let mut physical_max: i32 = 0;
        let mut in_touchpad = false;
        let mut in_finger = false;
        let mut current_bit_offset: u16 = 0;
        let mut finger_index: usize = 0;
        let mut finger_start_bit: u16 = 0;
        let mut pending_usage: Option<(u32, u32)> = None;  // (usage, usage_page)

        while i < data.len() {
            let prefix = data[i];
            let size = (prefix & 0x03) as usize;
            let item_type = (prefix >> 2) & 0x03;
            let tag = (prefix >> 4) & 0x0F;

            if prefix == 0xFE {
                if i + 2 < data.len() {
                    let long_size = data[i + 1] as usize;
                    i += 3 + long_size;
                } else {
                    break;
                }
                continue;
            }

            let actual_size = if size == 3 { 4 } else { size };
            if i + 1 + actual_size > data.len() {
                break;
            }

            let value = match actual_size {
                0 => 0u32,
                1 => data[i + 1] as u32,
                2 => u16::from_le_bytes([data[i + 1], data[i + 2]]) as u32,
                4 => u32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]),
                _ => 0,
            };

            match (item_type, tag) {
                (0, 0x08) => {
                    let bits = (report_size * report_count) as u16;

                    if in_touchpad {
                        if let Some((u, u_page)) = pending_usage.take() {
                            self.record_field(u, u_page, current_bit_offset, report_size as u16,
                                             logical_min, logical_max, in_finger, finger_index);
                        }
                    }

                    if report_id != 0 || bits > 0 {
                        self.input_reports.push(ReportInfo {
                            report_id,
                            size: bits,
                        });
                    }

                    current_bit_offset += bits;
                }
                (0, 0x09) => {
                    let bits = (report_size * report_count) as u16;
                    if report_id != 0 || bits > 0 {
                        self.output_reports.push(ReportInfo {
                            report_id,
                            size: bits,
                        });
                    }
                }
                (0, 0x0B) => {
                    let bits = (report_size * report_count) as u16;
                    if report_id != 0 || bits > 0 {
                        self.feature_reports.push(ReportInfo {
                            report_id,
                            size: bits,
                        });
                    }
                }
                (0, 0x0A) => {
                    let collection_type = value;
                    if (collection_type == 0x01 || collection_type == 0x02)
                        && usage_page == HID_USAGE_PAGE_DIGITIZER as u32
                        && usage == HID_USAGE_TOUCHPAD as u32 {
                        in_touchpad = true;
                        self.has_touchpad = true;
                        self.touchpad_layout.report_id = report_id;
                    }
                    if (collection_type == 0x01 || collection_type == 0x02)
                        && usage_page == HID_USAGE_PAGE_DIGITIZER as u32
                        && usage == HID_USAGE_TOUCH_SCREEN as u32 {
                        in_touchpad = true;
                        self.has_touchpad = true;
                        self.touchpad_layout.report_id = report_id;
                    }
                    if (collection_type == 0x00 || collection_type == 0x02)
                        && usage_page == HID_USAGE_PAGE_DIGITIZER as u32 && usage == 0x22 {
                        in_finger = true;
                        finger_start_bit = current_bit_offset;
                    }
                }
                (0, 0x0C) => {
                    if in_finger {
                        let finger_bits = current_bit_offset - finger_start_bit;
                        if self.touchpad_layout.contact_field_size == 0 {
                            self.touchpad_layout.contact_field_size = finger_bits;
                        }
                        in_finger = false;
                        finger_index += 1;
                    }
                    if !in_finger && in_touchpad {
                    }
                }

                (1, 0x00) => {
                    usage_page = value;
                }
                (1, 0x01) => {
                    logical_min = if actual_size == 1 {
                        (value as i8) as i32
                    } else if actual_size == 2 {
                        (value as i16) as i32
                    } else {
                        value as i32
                    };
                }
                (1, 0x02) => {
                    logical_max = if actual_size == 1 && (value & 0x80) != 0 {
                        value as i32  // Treat as unsigned for touchpad coords
                    } else if actual_size == 2 {
                        value as i32  // 16-bit, treat as unsigned
                    } else {
                        value as i32
                    };
                }
                (1, 0x03) => {
                }
                (1, 0x04) => {
                    physical_max = value as i32;
                }
                (1, 0x07) => {
                    report_size = value;
                }
                (1, 0x09) => {
                    report_count = value;
                }
                (1, 0x08) => {
                    report_id = value as u8;
                    current_bit_offset = 0;  // Reset for new report
                }

                (2, 0x00) => {
                    usage = value;
                    pending_usage = Some((value, usage_page));

                    if usage_page == HID_USAGE_PAGE_DIGITIZER as u32 {
                        match usage as u8 {
                            x if x == HID_USAGE_TOUCHPAD || x == HID_USAGE_TOUCH_SCREEN => {
                                self.has_touchpad = true;
                            }
                            x if x == HID_USAGE_TIP_SWITCH => self.has_tip = true,
                            x if x == HID_USAGE_CONTACT_ID => self.has_contact_id = true,
                            x if x == HID_USAGE_CONTACT_COUNT => {
                                self.max_contact_count = logical_max.max(1).min(10) as u8;
                            }
                            _ => {}
                        }
                    }
                    if usage_page == HID_USAGE_PAGE_GENERIC_DESKTOP as u32 {
                        match usage as u8 {
                            x if x == HID_USAGE_MOUSE => self.has_mouse = true,
                            x if x == HID_USAGE_KEYBOARD => self.has_keyboard = true,
                            x if x == HID_USAGE_X => {
                                self.has_x = true;
                                if logical_max > 0 {
                                    self.logical_max_x = logical_max;
                                    self.physical_max_x = physical_max;
                                }
                            }
                            x if x == HID_USAGE_Y => {
                                self.has_y = true;
                                if logical_max > 0 {
                                    self.logical_max_y = logical_max;
                                    self.physical_max_y = physical_max;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                (2, 0x0A) => {
                }
                _ => {}
            }

            i += 1 + actual_size;
        }

        self.touchpad_layout.total_report_size = current_bit_offset;
    }

    fn record_field(&mut self, usage: u32, usage_page: u32, bit_offset: u16, bit_size: u16,
                    logical_min: i32, logical_max: i32, in_finger: bool, finger_index: usize) {
        let loc = FieldLocation { bit_offset, bit_size };

        if usage_page == HID_USAGE_PAGE_DIGITIZER as u32 {
            match usage as u8 {
                0x56 => self.touchpad_layout.scan_time = loc,
                x if x == HID_USAGE_CONTACT_COUNT => self.touchpad_layout.contact_count = loc,
                x if x == HID_USAGE_TIP_SWITCH && in_finger && finger_index < 5 => {
                    self.touchpad_layout.contacts[finger_index].tip_switch = loc;
                }
                0x47 if in_finger && finger_index < 5 => {
                    self.touchpad_layout.contacts[finger_index].confidence = loc;
                }
                x if x == HID_USAGE_CONTACT_ID && in_finger && finger_index < 5 => {
                    self.touchpad_layout.contacts[finger_index].contact_id = loc;
                }
                0x48 if in_finger && finger_index < 5 => {
                    self.touchpad_layout.contacts[finger_index].width = loc;
                }
                0x49 if in_finger && finger_index < 5 => {
                    self.touchpad_layout.contacts[finger_index].height = loc;
                }
                0x30 if in_finger && finger_index < 5 => {
                    self.touchpad_layout.contacts[finger_index].pressure = loc;
                }
                _ => {}
            }
        }

        if usage_page == HID_USAGE_PAGE_GENERIC_DESKTOP as u32 && in_finger && finger_index < 5 {
            match usage as u8 {
                x if x == HID_USAGE_X => {
                    self.touchpad_layout.contacts[finger_index].x = loc;
                    self.logical_min_x = logical_min;
                    self.logical_max_x = logical_max.max(1);
                }
                x if x == HID_USAGE_Y => {
                    self.touchpad_layout.contacts[finger_index].y = loc;
                    self.logical_min_y = logical_min;
                    self.logical_max_y = logical_max.max(1);
                }
                _ => {}
            }
        }

        if usage_page == HID_USAGE_PAGE_BUTTON as u32 {
            match usage as u8 {
                x if x == HID_USAGE_BUTTON_PRIMARY => self.touchpad_layout.button = loc,
                x if x == HID_USAGE_BUTTON_SECONDARY => {
                }
                _ => {}
            }
        }
    }

    pub fn is_touchpad(&self) -> bool {
        self.has_touchpad && self.has_x && self.has_y
    }

    pub fn is_mouse(&self) -> bool {
        self.has_mouse && self.has_x && self.has_y
    }
}

impl Default for ReportDescriptor {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            input_reports: Vec::new(),
            output_reports: Vec::new(),
            feature_reports: Vec::new(),
            has_touchpad: false,
            has_mouse: false,
            has_keyboard: false,
            max_contact_count: 5,
            has_x: false,
            has_y: false,
            has_tip: false,
            has_contact_id: false,
            logical_min_x: 0,
            logical_min_y: 0,
            logical_max_x: 4096,
            logical_max_y: 4096,
            physical_max_x: 100,
            physical_max_y: 100,
            touchpad_layout: TouchpadLayout::default(),
        }
    }
}
