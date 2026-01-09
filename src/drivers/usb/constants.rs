// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub const REQ_GET_STATUS: u8 = 0x00;
pub const REQ_CLEAR_FEATURE: u8 = 0x01;
pub const REQ_SET_FEATURE: u8 = 0x03;
pub const REQ_SET_ADDRESS: u8 = 0x05;
pub const REQ_GET_DESCRIPTOR: u8 = 0x06;
pub const REQ_SET_DESCRIPTOR: u8 = 0x07;
pub const REQ_GET_CONFIGURATION: u8 = 0x08;
pub const REQ_SET_CONFIGURATION: u8 = 0x09;
pub const REQ_GET_INTERFACE: u8 = 0x0A;
pub const REQ_SET_INTERFACE: u8 = 0x0B;
pub const REQ_SYNCH_FRAME: u8 = 0x0C;
pub const RT_DEV: u8 = 0x00;
pub const RT_INTF: u8 = 0x01;
pub const RT_EP: u8 = 0x02;
pub const RT_OTHER: u8 = 0x03;
pub const DIR_OUT: u8 = 0x00;
pub const DIR_IN: u8 = 0x80;
pub const TYPE_STD: u8 = 0x00 << 5;
pub const TYPE_CLASS: u8 = 0x01 << 5;
pub const TYPE_VENDOR: u8 = 0x02 << 5;
pub const DT_DEVICE: u8 = 1;
pub const DT_CONFIG: u8 = 2;
pub const DT_STRING: u8 = 3;
pub const DT_INTERFACE: u8 = 4;
pub const DT_ENDPOINT: u8 = 5;
pub const DT_DEVICE_QUALIFIER: u8 = 6;
pub const DT_OTHER_SPEED_CONFIG: u8 = 7;
pub const DT_INTERFACE_POWER: u8 = 8;
pub const DT_OTG: u8 = 9;
pub const DT_DEBUG: u8 = 10;
pub const DT_INTERFACE_ASSOC: u8 = 11;
pub const DT_BOS: u8 = 15;
pub const DT_DEVICE_CAPABILITY: u8 = 16;
pub const DT_SS_EP_COMPANION: u8 = 48;
pub const DT_SSP_ISOCH_EP_COMPANION: u8 = 49;
pub const EP_TRANSFER_TYPE_MASK: u8 = 0x03;
pub const EP_TYPE_CONTROL: u8 = 0x00;
pub const EP_TYPE_ISOCHRONOUS: u8 = 0x01;
pub const EP_TYPE_BULK: u8 = 0x02;
pub const EP_TYPE_INTERRUPT: u8 = 0x03;
pub const EP_SYNC_TYPE_MASK: u8 = 0x0C;
pub const EP_SYNC_NONE: u8 = 0x00;
pub const EP_SYNC_ASYNC: u8 = 0x04;
pub const EP_SYNC_ADAPTIVE: u8 = 0x08;
pub const EP_SYNC_SYNC: u8 = 0x0C;
pub const EP_USAGE_TYPE_MASK: u8 = 0x30;
pub const EP_USAGE_DATA: u8 = 0x00;
pub const EP_USAGE_FEEDBACK: u8 = 0x10;
pub const EP_USAGE_IMPLICIT_FB: u8 = 0x20;
pub const CLASS_DEVICE: u8 = 0x00;
pub const CLASS_AUDIO: u8 = 0x01;
pub const CLASS_CDC: u8 = 0x02;
pub const CLASS_HID: u8 = 0x03;
pub const CLASS_PHYSICAL: u8 = 0x05;
pub const CLASS_IMAGE: u8 = 0x06;
pub const CLASS_PRINTER: u8 = 0x07;
pub const CLASS_MASS_STORAGE: u8 = 0x08;
pub const CLASS_HUB: u8 = 0x09;
pub const CLASS_CDC_DATA: u8 = 0x0A;
pub const CLASS_SMART_CARD: u8 = 0x0B;
pub const CLASS_CONTENT_SECURITY: u8 = 0x0D;
pub const CLASS_VIDEO: u8 = 0x0E;
pub const CLASS_PERSONAL_HEALTHCARE: u8 = 0x0F;
pub const CLASS_AUDIO_VIDEO: u8 = 0x10;
pub const CLASS_BILLBOARD: u8 = 0x11;
pub const CLASS_TYPE_C_BRIDGE: u8 = 0x12;
pub const CLASS_DIAGNOSTIC: u8 = 0xDC;
pub const CLASS_WIRELESS: u8 = 0xE0;
pub const CLASS_MISC: u8 = 0xEF;
pub const CLASS_APPLICATION: u8 = 0xFE;
pub const CLASS_VENDOR: u8 = 0xFF;
pub const FEATURE_ENDPOINT_HALT: u16 = 0;
pub const FEATURE_DEVICE_REMOTE_WAKEUP: u16 = 1;
pub const FEATURE_TEST_MODE: u16 = 2;
pub const DEFAULT_CONTROL_TIMEOUT_US: u32 = 5_000_000;
pub const DEFAULT_BULK_TIMEOUT_US: u32 = 5_000_000;
pub const DEFAULT_INTERRUPT_TIMEOUT_US: u32 = 1_000_000;
pub const USB2_MAX_CONTROL_PACKET: u16 = 64;
pub const USB3_MAX_CONTROL_PACKET: u16 = 512;
pub const DEFAULT_LANG_ID: u16 = 0x0409;
