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

pub const MAX_SLOTS: usize = 256;
pub const SLOT_ID_MIN: u8 = 1;
pub const MAX_ENDPOINTS: usize = 31;
pub const CONTEXT_SIZE_32: usize = 32;
pub const CONTEXT_SIZE_64: usize = 64;

pub const EP_TYPE_NOT_VALID: u8 = 0;
pub const EP_TYPE_ISOCH_OUT: u8 = 1;
pub const EP_TYPE_BULK_OUT: u8 = 2;
pub const EP_TYPE_INTERRUPT_OUT: u8 = 3;
pub const EP_TYPE_CONTROL: u8 = 4;
pub const EP_TYPE_ISOCH_IN: u8 = 5;
pub const EP_TYPE_BULK_IN: u8 = 6;
pub const EP_TYPE_INTERRUPT_IN: u8 = 7;

pub const EP_STATE_DISABLED: u8 = 0;
pub const EP_STATE_RUNNING: u8 = 1;
pub const EP_STATE_HALTED: u8 = 2;
pub const EP_STATE_STOPPED: u8 = 3;
pub const EP_STATE_ERROR: u8 = 4;

pub const MPS_LOW_SPEED: u16 = 8;
pub const MPS_FULL_SPEED: u16 = 8;
pub const MPS_HIGH_SPEED: u16 = 64;
pub const MPS_SUPER_SPEED: u16 = 512;
pub const MPS_SUPER_SPEED_PLUS: u16 = 512;

pub const DESC_TYPE_DEVICE: u8 = 0x01;
pub const DESC_TYPE_CONFIGURATION: u8 = 0x02;
pub const DESC_TYPE_STRING: u8 = 0x03;
pub const DESC_TYPE_INTERFACE: u8 = 0x04;
pub const DESC_TYPE_ENDPOINT: u8 = 0x05;
pub const DESC_TYPE_DEVICE_QUALIFIER: u8 = 0x06;
pub const DESC_TYPE_OTHER_SPEED: u8 = 0x07;
pub const DESC_TYPE_INTERFACE_POWER: u8 = 0x08;
pub const DESC_TYPE_BOS: u8 = 0x0F;
pub const DESC_TYPE_DEVICE_CAPABILITY: u8 = 0x10;
pub const DESC_TYPE_SS_EP_COMPANION: u8 = 0x30;
pub const DESC_TYPE_SSP_ISOCH_EP_COMPANION: u8 = 0x31;

pub const REQ_DIR_HOST_TO_DEVICE: u8 = 0x00;
pub const REQ_DIR_DEVICE_TO_HOST: u8 = 0x80;
pub const REQ_TYPE_STANDARD: u8 = 0x00;
pub const REQ_TYPE_CLASS: u8 = 0x20;
pub const REQ_TYPE_VENDOR: u8 = 0x40;
pub const REQ_RECIPIENT_DEVICE: u8 = 0x00;
pub const REQ_RECIPIENT_INTERFACE: u8 = 0x01;
pub const REQ_RECIPIENT_ENDPOINT: u8 = 0x02;
pub const REQ_RECIPIENT_OTHER: u8 = 0x03;

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
pub const REQ_SET_SEL: u8 = 0x30;
pub const REQ_SET_ISOCH_DELAY: u8 = 0x31;
