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

//! Intel WiFi constants and device IDs.
pub const INTEL_VENDOR_ID: u16 = 0x8086;
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    0x2723, 0x2725, 0x34F0, 0x3DF0, 0x4DF0, 0x2729, 0x272B, 0x51F0, 0x51F1, 0x54F0, 0x2526, 0x9DF0,
    0xA370, 0x31DC, 0x30DC, 0x24F3, 0x24F4, 0x24F5, 0x24F6, 0x24FD, 0x08B1, 0x08B2, 0x08B3, 0x08B4,
    0x095A, 0x095B,
];

pub mod csr {
    pub const HW_IF_CONFIG: u32 = 0x000;
    pub const INT_COALESCING: u32 = 0x004;
    pub const INT: u32 = 0x008;
    pub const INT_MASK: u32 = 0x00C;
    pub const FH_INT_STATUS: u32 = 0x010;
    pub const GPIO_IN: u32 = 0x018;
    pub const RESET: u32 = 0x020;
    pub const GP_CNTRL: u32 = 0x024;
    pub const HW_REV: u32 = 0x028;
    pub const EEPROM_REG: u32 = 0x02C;
    pub const EEPROM_GP: u32 = 0x030;
    pub const OTP_GP_REG: u32 = 0x034;
    pub const GIO_REG: u32 = 0x03C;
    pub const GP_UCODE_REG: u32 = 0x048;
    pub const GP_DRIVER_REG: u32 = 0x050;
    pub const UCODE_DRV_GP1: u32 = 0x054;
    pub const UCODE_DRV_GP1_SET: u32 = 0x058;
    pub const UCODE_DRV_GP1_CLR: u32 = 0x05C;
    pub const UCODE_DRV_GP2: u32 = 0x060;
    pub const DRAM_INT_TBL_REG: u32 = 0x0A0;
    pub const MAC_SHADOW_REG_CTRL: u32 = 0x0A8;
    pub const MSIX_HW_INT_CAUSES: u32 = 0x094;
    pub const MSIX_HW_INT_MASK: u32 = 0x098;
    pub const MSIX_FH_INT_CAUSES: u32 = 0x09C;
    pub const MSIX_FH_INT_MASK: u32 = 0x0A0;
    pub const DBG_HPET_MEM: u32 = 0x240;
    pub const DBG_LINK_PWR_MGMT: u32 = 0x250;
}

pub mod csr_bits {
    pub const GP_CNTRL_MAC_ACCESS_ENA: u32 = 0x00000001;
    pub const GP_CNTRL_MAC_CLOCK_READY: u32 = 0x00000002;
    pub const GP_CNTRL_INIT_DONE: u32 = 0x00000004;
    pub const GP_CNTRL_MAC_ACCESS_REQ: u32 = 0x00000008;
    pub const GP_CNTRL_SLEEP_EXIT_ON_INT: u32 = 0x00000010;
    pub const GP_CNTRL_XTAL_ON: u32 = 0x00000400;
    pub const GP_CNTRL_REG_FLAG_INIT_DONE: u32 = 0x00000004;
    pub const GP_CNTRL_REG_FLAG_MAC_CLOCK_READY: u32 = 0x00000001;
    pub const GP_CNTRL_REG_FLAG_GOING_TO_SLEEP: u32 = 0x00000010;
    pub const RESET_REG_FLAG_NEVO_RESET: u32 = 0x00000001;
    pub const RESET_REG_FLAG_FORCE_NMI: u32 = 0x00000002;
    pub const RESET_REG_FLAG_SW_RESET: u32 = 0x00000080;
    pub const RESET_REG_FLAG_MASTER_DISABLED: u32 = 0x00000100;
    pub const RESET_REG_FLAG_STOP_MASTER: u32 = 0x00000200;
    pub const INT_BIT_FH_RX: u32 = 1 << 26;
    pub const INT_BIT_HW_ERR: u32 = 1 << 29;
    pub const INT_BIT_FH_TX: u32 = 1 << 27;
    pub const INT_BIT_SW_ERR: u32 = 1 << 25;
    pub const INT_BIT_RF_KILL: u32 = 1 << 7;
    pub const INT_BIT_CT_KILL: u32 = 1 << 6;
    pub const INT_BIT_WAKEUP: u32 = 1 << 1;
    pub const INT_BIT_ALIVE: u32 = 1 << 0;
}

pub mod fh {
    pub const RSCSR_CHNL0_STTS_WPTR_REG: u32 = 0x1BC0;
    pub const RSCSR_CHNL0_RBDCB_BASE_REG: u32 = 0x1BC8;
    pub const RSCSR_CHNL0_WPTR: u32 = 0x1BC8;
    pub const RSCSR_CHNL0_RBDCB_WPTR_REG: u32 = 0x1BC8;
    pub const RCSR_CHNL0_CONFIG_REG: u32 = 0x1F40;
    pub const RCSR_RX_CONFIG_REG_IRQ_DEST_HOST: u32 = 1 << 12;
    pub const RCSR_RX_CONFIG_REG_SINGLE_FRAME: u32 = 1 << 11;
    pub const RCSR_RX_CONFIG_REG_RB_SIZE_4K: u32 = 0 << 8;
    pub const RCSR_RX_CONFIG_REG_RBDCB_SIZE_8: u32 = 0 << 4;
    pub const RCSR_RX_CONFIG_REG_RB_TIMEOUT_IMMEDIATE: u32 = 1 << 0;
    pub const TCSR_CHNL_TX_CONFIG_REG: u32 = 0x1D00;
    pub const TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_PAUSE: u32 = 0x00000000;
    pub const TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE: u32 = 0x80000000;
    pub const TSSR_TX_STATUS_REG: u32 = 0x1EA0;
}

pub mod cmd {
    pub const MVM_ALIVE: u32 = 0x01;
    pub const REPLY_ERROR: u32 = 0x02;
    pub const ECHO_CMD: u32 = 0x03;
    pub const INIT_COMPLETE_NOTIF: u32 = 0x04;
    pub const PHY_CONTEXT_CMD: u32 = 0x08;
    pub const DBG_CFG: u32 = 0x09;
    pub const SCAN_ITERATION_COMPLETE_UMAC: u32 = 0x0B;
    pub const SCAN_CFG_CMD: u32 = 0x0C;
    pub const SCAN_REQ_UMAC: u32 = 0x0D;
    pub const SCAN_ABORT_UMAC: u32 = 0x0E;
    pub const SCAN_COMPLETE_UMAC: u32 = 0x0F;
    pub const BA_WINDOW_STATUS_NOTIFICATION_ID: u32 = 0x10;
    pub const ADD_STA_KEY: u32 = 0x17;
    pub const ADD_STA: u32 = 0x18;
    pub const REMOVE_STA: u32 = 0x19;
    pub const TX_CMD: u32 = 0x1C;
    pub const TXPATH_FLUSH: u32 = 0x1E;
    pub const MGMT_MCAST_KEY: u32 = 0x1F;
    pub const WEP_KEY: u32 = 0x20;
    pub const STA_REMOVE_KEY: u32 = 0x22;
    pub const MAC_CONTEXT_CMD: u32 = 0x28;
    pub const TIME_EVENT_CMD: u32 = 0x29;
    pub const TIME_EVENT_NOTIFICATION: u32 = 0x2A;
    pub const BINDING_CONTEXT_CMD: u32 = 0x2B;
    pub const TIME_QUOTA_CMD: u32 = 0x2C;
    pub const NON_QOS_TX_COUNTER_CMD: u32 = 0x2D;
    pub const LEDS_CMD: u32 = 0x48;
    pub const LQ_CMD: u32 = 0x4E;
    pub const FW_PAGING_BLOCK_CMD: u32 = 0x4F;
    pub const CALIB_RES_NOTIF_PHY_DB: u32 = 0x6B;
    pub const PHY_DB_CMD: u32 = 0x6C;
    pub const SCAN_OFFLOAD_REQUEST_CMD: u32 = 0x51;
    pub const SCAN_OFFLOAD_ABORT_CMD: u32 = 0x52;
    pub const HOT_SPOT_CMD: u32 = 0x53;
    pub const NVM_ACCESS_CMD: u32 = 0x88;
    pub const SET_CALIB_DEFAULT_CMD: u32 = 0x8E;
    pub const BEACON_NOTIFICATION: u32 = 0x90;
    pub const BEACON_TEMPLATE_CMD: u32 = 0x91;
    pub const TX_ANT_CONFIGURATION_CMD: u32 = 0x98;
    pub const BT_CONFIG: u32 = 0x9B;
    pub const STATISTICS_CMD: u32 = 0x9C;
    pub const STATISTICS_NOTIFICATION: u32 = 0x9D;
    pub const EOSP_NOTIFICATION: u32 = 0x9E;
    pub const REDUCE_TX_POWER_CMD: u32 = 0x9F;
    pub const CARD_STATE_NOTIFICATION: u32 = 0xA1;
    pub const MISSED_BEACONS_NOTIFICATION: u32 = 0xA2;
    pub const MAC_PM_POWER_TABLE: u32 = 0xA9;
    pub const MFUART_LOAD_NOTIFICATION: u32 = 0xB1;
    pub const RSS_CONFIG_CMD: u32 = 0xB3;
    pub const REPLY_RX_PHY_CMD: u32 = 0xC0;
    pub const REPLY_RX_MPDU_CMD: u32 = 0xC1;
    pub const FRAME_RELEASE: u32 = 0xC3;
    pub const BA_NOTIF: u32 = 0xC5;
    pub const MCC_UPDATE_CMD: u32 = 0xC8;
    pub const MCC_CHUB_UPDATE_CMD: u32 = 0xC9;
    pub const MARKER_CMD: u32 = 0xCB;
    pub const BT_COEX_PRIO_TABLE: u32 = 0xCC;
    pub const BT_COEX_PROT_ENV: u32 = 0xCD;
    pub const BT_PROFILE_NOTIFICATION: u32 = 0xCE;
    pub const REPLY_SF_CFG_CMD: u32 = 0xD1;
    pub const REPLY_BEACON_FILTERING_CMD: u32 = 0xD2;
    pub const DTS_MEASUREMENT_NOTIFICATION: u32 = 0xDD;
    pub const DEBUG_LOG_MSG: u32 = 0xF7;
    pub const BCAST_FILTER_CMD: u32 = 0xCF;
    pub const MCAST_FILTER_CMD: u32 = 0xD0;
    pub const D3_CONFIG_CMD: u32 = 0xD3;
    pub const PROT_OFFLOAD_CONFIG_CMD: u32 = 0xD4;
    pub const OFFLOADS_QUERY_CMD: u32 = 0xD5;
    pub const D0I3_END_CMD: u32 = 0xED;
}

pub const NUM_TFD_QUEUES: usize = 31;
pub const TFD_QUEUE_SIZE_LOG: u32 = 8;
pub const TFD_QUEUE_SIZE: usize = 1 << TFD_QUEUE_SIZE_LOG;
pub const TFD_QUEUE_SIZE_MASK: usize = TFD_QUEUE_SIZE - 1;
pub const RX_QUEUE_SIZE_LOG: u32 = 8;
pub const RX_QUEUE_SIZE: usize = 1 << RX_QUEUE_SIZE_LOG;
pub const RX_QUEUE_SIZE_MASK: usize = RX_QUEUE_SIZE - 1;
pub const RX_BUFFER_SIZE: usize = 4096;
pub const TX_BUFFER_SIZE: usize = 4096;
pub const MAX_CMD_PAYLOAD_SIZE: usize = 320;
pub const ALIVE_TIMEOUT_MS: u64 = 2000;
pub const INIT_TIMEOUT_MS: u64 = 5000;
pub const SCAN_TIMEOUT_MS: u64 = 10000;
pub const CONNECT_TIMEOUT_MS: u64 = 5000;
pub const APM_INIT_TIMEOUT_US: u64 = 25000;
pub const NIC_ACCESS_TIMEOUT_US: u64 = 15000;
pub const STOP_MASTER_TIMEOUT_US: u64 = 100000;
pub const INT_COALESCING_TIMEOUT: u32 = 64;
pub const TFD_ALIGNMENT: usize = 256;
pub const TB_ALIGNMENT: usize = 64;
pub const BC_TBL_ALIGNMENT: usize = 16;
pub const RX_BD_ALIGNMENT: usize = 256;
pub const RX_STATUS_ALIGNMENT: usize = 16;
pub const RX_BUFFER_ALIGNMENT: usize = 4096;
pub const DMA_ALIGNMENT: usize = 4096;
pub const SCAN_CMD_SIZE: usize = 256;
pub const MAC_CONTEXT_CMD_SIZE: usize = 128;
pub const AUTH_CMD_SIZE: usize = 256;
pub const RSSI_INVALID: i8 = -100;
pub const FW_MEM_EXTENDED_START: u32 = 0x40000;
pub const FW_MEM_EXTENDED_END: u32 = 0x57FFF;
pub const MIN_FW_API_VERSION: u16 = 22;
pub const MAX_FW_API_VERSION: u16 = 77;
pub const PRPH_BASE: u32 = 0x44000;
pub const PRPH_DWORD: u32 = PRPH_BASE + 0x0C;
pub const PRPH_DATA: u32 = PRPH_BASE + 0x10;
pub const HBUS_TARG_MEM_RADDR: u32 = 0x40000;
pub const HBUS_TARG_MEM_WDAT: u32 = 0x40004;
pub const TX_QUEUE_WRITE_PTR_BASE: u32 = 0x1C08;
pub const CSR_UCODE_BASE: u32 = 0x044000;
pub const NVM_MAC_ADDR: u32 = 0x00A01020;
pub const DMA_BLOCK_SIZE: usize = 0x1000;
pub const KERNEL_PHYS_MASK: u64 = 0xFFFF_FFFF;
pub const KERNEL_RESERVED_SIZE: u64 = 0x0200_0000;
pub const IWL_FW_MAGIC: u32 = 0x0a4c5749;
pub const FW_API_VERSION_MASK: u32 = 0xFFFF;
pub const ALL_INTS_MASK: u32 = 0xFFFF_FFFF;
pub const INT_MASK_DISABLED: u32 = 0x0000_0000;
pub const RX_STATUS_PTR_MASK: u32 = 0xFFF;
pub const PRPH_READ_FLAG: u32 = 3 << 24;
pub const IEEE80211_FC_TODS: u16 = 0x0100;
pub const FRAME_TYPE_MASK: u16 = 0x000C;
pub const FRAME_SUBTYPE_MASK: u16 = 0x00F0;
pub const INFINITE_LIFETIME: u32 = 0xFFFF_FFFF;
