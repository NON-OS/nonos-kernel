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

pub const XHCI_CLASS: u8 = 0x0C;
pub const XHCI_SUBCLASS: u8 = 0x03;
pub const XHCI_PROGIF: u8 = 0x30;
pub const TRB_ALIGNMENT: u64 = 16;
pub const DMA_MIN_ALIGNMENT: usize = 64;
pub const MAX_TRANSFER_SIZE: usize = 1024 * 1024;
pub const MAX_DESCRIPTOR_SIZE: usize = 4096;
pub const MIN_DESCRIPTOR_SIZE: usize = 8;
pub const ENUMERATION_RATE_LIMIT_MS: u64 = 1000;
pub const MAX_ENUMERATION_ATTEMPTS: u32 = 5;
pub const DEFAULT_TIMEOUT_SPINS: u32 = 2_000_000;
pub const MAX_TIMEOUT_SPINS: u32 = 10_000_000;
pub const CONTROLLER_RESET_TIMEOUT: u32 = 1_000_000;
pub const PORT_RESET_TIMEOUT: u32 = 500_000;
pub const CAP_CAPLENGTH: usize = 0x00;
pub const CAP_HCSPARAMS1: usize = 0x04;
pub const CAP_HCSPARAMS2: usize = 0x08;
pub const CAP_HCSPARAMS3: usize = 0x0C;
pub const CAP_HCCPARAMS1: usize = 0x10;
pub const CAP_DBOFF: usize = 0x14;
pub const CAP_RTSOFF: usize = 0x18;
pub const CAP_HCCPARAMS2: usize = 0x1C;
pub const HCSPARAMS1_MAXSLOTS_MASK: u32 = 0xFF;
pub const HCSPARAMS1_MAXINTRS_MASK: u32 = 0x7FF << 8;
pub const HCSPARAMS1_MAXINTRS_SHIFT: u32 = 8;
pub const HCSPARAMS1_MAXPORTS_MASK: u32 = 0xFF << 24;
pub const HCSPARAMS1_MAXPORTS_SHIFT: u32 = 24;
pub const HCSPARAMS2_IST_MASK: u32 = 0xF;
pub const HCSPARAMS2_ERST_MAX_MASK: u32 = 0xF << 4;
pub const HCSPARAMS2_ERST_MAX_SHIFT: u32 = 4;
pub const HCSPARAMS2_SPB_HI_MASK: u32 = 0x1F << 21;
pub const HCSPARAMS2_SPB_HI_SHIFT: u32 = 21;
pub const HCSPARAMS2_SPR: u32 = 1 << 26;
pub const HCSPARAMS2_SPB_LO_MASK: u32 = 0x1F << 27;
pub const HCSPARAMS2_SPB_LO_SHIFT: u32 = 27;
pub const HCCPARAMS1_AC64: u32 = 1 << 0;
pub const HCCPARAMS1_BNC: u32 = 1 << 1;
pub const HCCPARAMS1_CSZ: u32 = 1 << 2;
pub const HCCPARAMS1_PPC: u32 = 1 << 3;
pub const HCCPARAMS1_PIND: u32 = 1 << 4;
pub const HCCPARAMS1_LHRC: u32 = 1 << 5;
pub const HCCPARAMS1_LTC: u32 = 1 << 6;
pub const HCCPARAMS1_NSS: u32 = 1 << 7;
pub const HCCPARAMS1_PAE: u32 = 1 << 8;
pub const HCCPARAMS1_SPC: u32 = 1 << 9;
pub const HCCPARAMS1_SEC: u32 = 1 << 10;
pub const HCCPARAMS1_CFC: u32 = 1 << 11;
pub const HCCPARAMS1_MAXPSASIZE_MASK: u32 = 0xF << 12;
pub const HCCPARAMS1_MAXPSASIZE_SHIFT: u32 = 12;
pub const HCCPARAMS1_XECP_MASK: u32 = 0xFFFF << 16;
pub const HCCPARAMS1_XECP_SHIFT: u32 = 16;
pub const OP_USBCMD: usize = 0x00;
pub const OP_USBSTS: usize = 0x04;
pub const OP_PAGESIZE: usize = 0x08;
pub const OP_DNCTRL: usize = 0x14;
pub const OP_CRCR: usize = 0x18;
pub const OP_DCBAAP: usize = 0x30;
pub const OP_CONFIG: usize = 0x38;
pub const OP_PORTSC_BASE: usize = 0x400;
pub const OP_PORT_REG_STRIDE: usize = 0x10;
pub const USBCMD_RS: u32 = 1 << 0;
pub const USBCMD_HCRST: u32 = 1 << 1;
pub const USBCMD_INTE: u32 = 1 << 2;
pub const USBCMD_HSEE: u32 = 1 << 3;
pub const USBCMD_LHCRST: u32 = 1 << 7;
pub const USBCMD_CSS: u32 = 1 << 8;
pub const USBCMD_CRS: u32 = 1 << 9;
pub const USBCMD_EWE: u32 = 1 << 10;
pub const USBCMD_EU3S: u32 = 1 << 11;
pub const USBCMD_CME: u32 = 1 << 13;
pub const USBCMD_ETE: u32 = 1 << 14;
pub const USBCMD_TSC_EN: u32 = 1 << 15;
pub const USBSTS_HCH: u32 = 1 << 0;
pub const USBSTS_HSE: u32 = 1 << 2;
pub const USBSTS_EINT: u32 = 1 << 3;
pub const USBSTS_PCD: u32 = 1 << 4;
pub const USBSTS_SSS: u32 = 1 << 8;
pub const USBSTS_RSS: u32 = 1 << 9;
pub const USBSTS_SRE: u32 = 1 << 10;
pub const USBSTS_CNR: u32 = 1 << 11;
pub const USBSTS_HCE: u32 = 1 << 12;
pub const PORTSC_CCS: u32 = 1 << 0;
pub const PORTSC_PED: u32 = 1 << 1;
pub const PORTSC_OCA: u32 = 1 << 3;
pub const PORTSC_PR: u32 = 1 << 4;
pub const PORTSC_PLS_MASK: u32 = 0xF << 5;
pub const PORTSC_PLS_SHIFT: u32 = 5;
pub const PORTSC_PP: u32 = 1 << 9;
pub const PORTSC_SPEED_MASK: u32 = 0xF << 10;
pub const PORTSC_SPEED_SHIFT: u32 = 10;
pub const PORTSC_PIC_MASK: u32 = 0x3 << 14;
pub const PORTSC_LWS: u32 = 1 << 16;
pub const PORTSC_CSC: u32 = 1 << 17;
pub const PORTSC_PEC: u32 = 1 << 18;
pub const PORTSC_WRC: u32 = 1 << 19;
pub const PORTSC_OCC: u32 = 1 << 20;
pub const PORTSC_PRC: u32 = 1 << 21;
pub const PORTSC_PLC: u32 = 1 << 22;
pub const PORTSC_CEC: u32 = 1 << 23;
pub const PORTSC_CAS: u32 = 1 << 24;
pub const PORTSC_WCE: u32 = 1 << 25;
pub const PORTSC_WDE: u32 = 1 << 26;
pub const PORTSC_WOE: u32 = 1 << 27;
pub const PORTSC_DR: u32 = 1 << 30;
pub const PORTSC_WPR: u32 = 1 << 31;

pub const PORTSC_CHANGE_BITS: u32 =
    PORTSC_CSC | PORTSC_PEC | PORTSC_WRC | PORTSC_OCC | PORTSC_PRC | PORTSC_PLC | PORTSC_CEC;

pub const PLS_U0: u32 = 0;
pub const PLS_U1: u32 = 1;
pub const PLS_U2: u32 = 2;
pub const PLS_U3: u32 = 3;
pub const PLS_DISABLED: u32 = 4;
pub const PLS_RXDETECT: u32 = 5;
pub const PLS_INACTIVE: u32 = 6;
pub const PLS_POLLING: u32 = 7;
pub const PLS_RECOVERY: u32 = 8;
pub const PLS_HOT_RESET: u32 = 9;
pub const PLS_COMPLIANCE: u32 = 10;
pub const PLS_TEST: u32 = 11;
pub const PLS_RESUME: u32 = 15;
pub const SPEED_FULL: u32 = 1;
pub const SPEED_LOW: u32 = 2;
pub const SPEED_HIGH: u32 = 3;
pub const SPEED_SUPER: u32 = 4;
pub const SPEED_SUPER_PLUS: u32 = 5;
pub const RT_MFINDEX: usize = 0x00;
pub const RT_IR0_IMAN: usize = 0x20;
pub const RT_IR0_IMOD: usize = 0x24;
pub const RT_IR0_ERSTSZ: usize = 0x28;
pub const RT_IR0_ERSTBA: usize = 0x30;
pub const RT_IR0_ERDP: usize = 0x38;
pub const RT_IR_STRIDE: usize = 0x20;
pub const IMAN_IP: u32 = 1 << 0;
pub const IMAN_IE: u32 = 1 << 1;
pub const ERDP_DESI_MASK: u64 = 0x7;
pub const ERDP_EHB: u64 = 1 << 3;
pub const CRCR_RCS: u64 = 1 << 0;
pub const CRCR_CS: u64 = 1 << 1;
pub const CRCR_CA: u64 = 1 << 2;
pub const CRCR_CRR: u64 = 1 << 3;
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
pub const DEFAULT_CMD_RING_SIZE: usize = 256;
pub const DEFAULT_EVENT_RING_SIZE: usize = 256;
pub const DEFAULT_TRANSFER_RING_SIZE: usize = 256;
pub const MIN_RING_SIZE: usize = 16;
pub const MAX_RING_SIZE: usize = 4096;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_portsc_change_bits() {
        assert_eq!(PORTSC_CHANGE_BITS & PORTSC_CSC, PORTSC_CSC);
        assert_eq!(PORTSC_CHANGE_BITS & PORTSC_PED, 0);
    }

    #[test]
    fn test_trb_alignment() {
        assert_eq!(TRB_ALIGNMENT, 16);
        assert!(DMA_MIN_ALIGNMENT >= TRB_ALIGNMENT as usize);
    }
}
