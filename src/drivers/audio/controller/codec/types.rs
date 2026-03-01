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
use super::quirks::CodecQuirks;
use super::names::{vendor_name, device_name};

#[derive(Clone, Copy, Debug)]
pub(crate) struct CodecInfo {
    pub cad: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub revision_id: u32,
    pub fn_group_start: u8,
    pub fn_group_count: u8,
    pub quirks: CodecQuirks,
}

impl CodecInfo {
    pub const fn empty() -> Self {
        Self {
            cad: 0,
            vendor_id: 0,
            device_id: 0,
            revision_id: 0,
            fn_group_start: 0,
            fn_group_count: 0,
            quirks: CodecQuirks::empty(),
        }
    }

    pub fn vendor_name(&self) -> &'static str {
        vendor_name(self.vendor_id)
    }

    pub fn device_name(&self) -> &'static str {
        device_name(self.vendor_id, self.device_id)
    }

    pub fn is_digital(&self) -> bool {
        matches!(self.vendor_id, 0x8086 | 0x10DE | 0x1002)
    }

    pub fn is_virtual(&self) -> bool {
        matches!(self.vendor_id, 0x1AF4 | 0x15AD)
    }

    pub fn full_id(&self) -> u32 {
        ((self.vendor_id as u32) << 16) | (self.device_id as u32)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct WidgetInfo {
    pub nid: u8,
    pub widget_type: u8,
    pub caps: u32,
    pub conn_len: u8,
    pub conn_first: u8,
    pub pin_caps: u32,
    pub pin_config: u32,
    pub amp_in_caps: u32,
    pub amp_out_caps: u32,
}

impl WidgetInfo {
    pub fn has_out_amp(&self) -> bool {
        (self.caps & (1 << 2)) != 0
    }

    pub fn has_in_amp(&self) -> bool {
        (self.caps & (1 << 1)) != 0
    }

    pub fn is_output_pin(&self) -> bool {
        self.widget_type == WIDGET_TYPE_PIN && (self.pin_caps & (1 << 4)) != 0
    }

    pub fn is_input_pin(&self) -> bool {
        self.widget_type == WIDGET_TYPE_PIN && (self.pin_caps & (1 << 5)) != 0
    }

    pub fn pin_device_type(&self) -> u8 {
        ((self.pin_config >> 20) & 0xF) as u8
    }

    pub fn pin_connectivity(&self) -> u8 {
        ((self.pin_config >> 30) & 0x3) as u8
    }

    pub fn is_connected(&self) -> bool {
        self.pin_connectivity() != 1
    }

    pub fn out_amp_steps(&self) -> u8 {
        ((self.amp_out_caps >> 8) & 0x7F) as u8
    }

    pub fn in_amp_steps(&self) -> u8 {
        ((self.amp_in_caps >> 8) & 0x7F) as u8
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AudioPath {
    pub dac_nid: u8,
    pub path: [u8; 8],
    pub path_len: u8,
    pub pin_nid: u8,
    pub device_type: u8,
    pub active: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct CodecPaths {
    pub output_paths: [AudioPath; MAX_OUTPUT_PATHS],
    pub output_count: usize,
    pub primary_output: usize,
}

impl Default for CodecPaths {
    fn default() -> Self {
        Self {
            output_paths: [AudioPath::default(); MAX_OUTPUT_PATHS],
            output_count: 0,
            primary_output: 0,
        }
    }
}
