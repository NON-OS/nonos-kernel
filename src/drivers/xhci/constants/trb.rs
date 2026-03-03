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

pub const TRB_TYPE_NORMAL: u32 = 1;
pub const TRB_TYPE_SETUP_STAGE: u32 = 2;
pub const TRB_TYPE_DATA_STAGE: u32 = 3;
pub const TRB_TYPE_STATUS_STAGE: u32 = 4;
pub const TRB_TYPE_ISOCH: u32 = 5;
pub const TRB_TYPE_LINK: u32 = 6;
pub const TRB_TYPE_EVENT_DATA: u32 = 7;
pub const TRB_TYPE_NOOP_TRANSFER: u32 = 8;

pub const TRB_TYPE_ENABLE_SLOT_CMD: u32 = 9;
pub const TRB_TYPE_DISABLE_SLOT_CMD: u32 = 10;
pub const TRB_TYPE_ADDRESS_DEVICE_CMD: u32 = 11;
pub const TRB_TYPE_CONFIGURE_EP_CMD: u32 = 12;
pub const TRB_TYPE_EVALUATE_CTX_CMD: u32 = 13;
pub const TRB_TYPE_RESET_EP_CMD: u32 = 14;
pub const TRB_TYPE_STOP_EP_CMD: u32 = 15;
pub const TRB_TYPE_SET_TR_DEQUEUE_CMD: u32 = 16;
pub const TRB_TYPE_RESET_DEVICE_CMD: u32 = 17;
pub const TRB_TYPE_FORCE_EVENT_CMD: u32 = 18;
pub const TRB_TYPE_NEGOTIATE_BW_CMD: u32 = 19;
pub const TRB_TYPE_SET_LATENCY_CMD: u32 = 20;
pub const TRB_TYPE_GET_PORT_BW_CMD: u32 = 21;
pub const TRB_TYPE_FORCE_HEADER_CMD: u32 = 22;
pub const TRB_TYPE_NOOP_CMD: u32 = 23;
pub const TRB_TYPE_GET_EXT_PROPERTY_CMD: u32 = 24;
pub const TRB_TYPE_SET_EXT_PROPERTY_CMD: u32 = 25;

pub const TRB_TYPE_TRANSFER_EVENT: u32 = 32;
pub const TRB_TYPE_CMD_COMPLETION_EVENT: u32 = 33;
pub const TRB_TYPE_PORT_STATUS_EVENT: u32 = 34;
pub const TRB_TYPE_BANDWIDTH_REQUEST_EVENT: u32 = 35;
pub const TRB_TYPE_DOORBELL_EVENT: u32 = 36;
pub const TRB_TYPE_HOST_CONTROLLER_EVENT: u32 = 37;
pub const TRB_TYPE_DEVICE_NOTIFICATION_EVENT: u32 = 38;
pub const TRB_TYPE_MFINDEX_WRAP_EVENT: u32 = 39;

pub const TRB_CYCLE: u32 = 1 << 0;
pub const TRB_ENT: u32 = 1 << 1;
pub const TRB_ISP: u32 = 1 << 2;
pub const TRB_NS: u32 = 1 << 3;
pub const TRB_CH: u32 = 1 << 4;
pub const TRB_IOC: u32 = 1 << 5;
pub const TRB_IDT: u32 = 1 << 6;
pub const TRB_BEI: u32 = 1 << 9;
pub const TRB_TYPE_SHIFT: u32 = 10;
pub const TRB_TYPE_MASK: u32 = 0x3F << 10;

pub const TRT_NO_DATA: u32 = 0 << 16;
pub const TRT_OUT_DATA: u32 = 2 << 16;
pub const TRT_IN_DATA: u32 = 3 << 16;

pub const TRB_DIR_IN: u32 = 1 << 16;

pub const LINK_TC: u32 = 1 << 1;

pub const CC_INVALID: u8 = 0;
pub const CC_SUCCESS: u8 = 1;
pub const CC_DATA_BUFFER_ERROR: u8 = 2;
pub const CC_BABBLE_DETECTED: u8 = 3;
pub const CC_USB_TRANSACTION_ERROR: u8 = 4;
pub const CC_TRB_ERROR: u8 = 5;
pub const CC_STALL_ERROR: u8 = 6;
pub const CC_RESOURCE_ERROR: u8 = 7;
pub const CC_BANDWIDTH_ERROR: u8 = 8;
pub const CC_NO_SLOTS_AVAILABLE: u8 = 9;
pub const CC_INVALID_STREAM_TYPE: u8 = 10;
pub const CC_SLOT_NOT_ENABLED: u8 = 11;
pub const CC_ENDPOINT_NOT_ENABLED: u8 = 12;
pub const CC_SHORT_PACKET: u8 = 13;
pub const CC_RING_UNDERRUN: u8 = 14;
pub const CC_RING_OVERRUN: u8 = 15;
pub const CC_VF_EVENT_RING_FULL: u8 = 16;
pub const CC_PARAMETER_ERROR: u8 = 17;
pub const CC_BANDWIDTH_OVERRUN: u8 = 18;
pub const CC_CONTEXT_STATE_ERROR: u8 = 19;
pub const CC_NO_PING_RESPONSE: u8 = 20;
pub const CC_EVENT_RING_FULL: u8 = 21;
pub const CC_INCOMPATIBLE_DEVICE: u8 = 22;
pub const CC_MISSED_SERVICE: u8 = 23;
pub const CC_COMMAND_RING_STOPPED: u8 = 24;
pub const CC_COMMAND_ABORTED: u8 = 25;
pub const CC_STOPPED: u8 = 26;
pub const CC_STOPPED_LENGTH_INVALID: u8 = 27;
pub const CC_STOPPED_SHORT_PACKET: u8 = 28;
pub const CC_MAX_EXIT_LATENCY_TOO_LARGE: u8 = 29;
pub const CC_ISOCH_BUFFER_OVERRUN: u8 = 31;
pub const CC_EVENT_LOST: u8 = 32;
pub const CC_UNDEFINED: u8 = 33;
pub const CC_INVALID_STREAM_ID: u8 = 34;
pub const CC_SECONDARY_BANDWIDTH: u8 = 35;
pub const CC_SPLIT_TRANSACTION: u8 = 36;

pub const VALID_TRANSFER_TRB_TYPES: &[u32] = &[
    TRB_TYPE_NORMAL,
    TRB_TYPE_SETUP_STAGE,
    TRB_TYPE_DATA_STAGE,
    TRB_TYPE_STATUS_STAGE,
    TRB_TYPE_ISOCH,
    TRB_TYPE_LINK,
    TRB_TYPE_EVENT_DATA,
    TRB_TYPE_NOOP_TRANSFER,
];

pub const VALID_COMMAND_TRB_TYPES: &[u32] = &[
    TRB_TYPE_ENABLE_SLOT_CMD,
    TRB_TYPE_DISABLE_SLOT_CMD,
    TRB_TYPE_ADDRESS_DEVICE_CMD,
    TRB_TYPE_CONFIGURE_EP_CMD,
    TRB_TYPE_EVALUATE_CTX_CMD,
    TRB_TYPE_RESET_EP_CMD,
    TRB_TYPE_STOP_EP_CMD,
    TRB_TYPE_SET_TR_DEQUEUE_CMD,
    TRB_TYPE_RESET_DEVICE_CMD,
    TRB_TYPE_NOOP_CMD,
];
