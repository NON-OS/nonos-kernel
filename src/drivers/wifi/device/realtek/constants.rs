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

pub const REALTEK_VENDOR_ID: u16 = 0x10EC;

pub const REALTEK_WIFI_DEVICE_IDS: &[u16] = &[
    0xC821, // RTL8821CE
    0xC822, // RTL8822CE
    0xC82F, // RTL8822CE
    0xB822, // RTL8822BE
    0xB852, // RTL8852BE
    0xC852, // RTL8852CE
    0x8852, // RTL8852AE
    0xA852, // RTL8852AE
    0xC862, // RTL8852BE
    0xD723, // RTL8723DE
    0xB723, // RTL8723BE
    0x8723, // RTL8723AE
    0xC82C, // RTL8822CE
    0xB82B, // RTL8822BE
    0xC812, // RTL8812CE
    0x8812, // RTL8812AE
    0xB812, // RTL8812BE
];

pub mod regs {
    pub const SYS_FUNC_EN: u16 = 0x0002;
    pub const SYS_CLK: u16 = 0x0008;
    pub const SYS_ISO_CTRL: u16 = 0x0000;
    pub const SYS_PWR_CTRL: u16 = 0x0004;
    pub const AFE_MISC: u16 = 0x0010;
    pub const AFE_PLL_CTRL: u16 = 0x0028;
    pub const EFUSE_CTRL: u16 = 0x0030;
    pub const EFUSE_TEST: u16 = 0x0034;
    pub const GPIO_MUXCFG: u16 = 0x0040;
    pub const GPIO_IO_SEL: u16 = 0x0042;
    pub const GPIO_PIN_CTRL: u16 = 0x0044;
    pub const GPIO_INTM: u16 = 0x0048;
    pub const LEDCFG0: u16 = 0x004C;
    pub const LEDCFG1: u16 = 0x004D;
    pub const LEDCFG2: u16 = 0x004E;
    pub const MCUFWDL: u16 = 0x0080;
    pub const HMEBOX_EXT_0: u16 = 0x0088;
    pub const HMEBOX_EXT_1: u16 = 0x008A;
    pub const HMEBOX_EXT_2: u16 = 0x008C;
    pub const HMEBOX_EXT_3: u16 = 0x008E;
    pub const BIST_SCAN: u16 = 0x00D0;
    pub const WLAN_INFO: u16 = 0x00E0;
    pub const CR: u16 = 0x0100;
    pub const PBP: u16 = 0x0104;
    pub const PKT_BUFF_ACCESS_CTRL: u16 = 0x0106;
    pub const TRXDMA_CTRL: u16 = 0x010C;
    pub const TRXFF_BNDY: u16 = 0x0114;
    pub const TRXFF_STATUS: u16 = 0x0118;
    pub const RXFF_PTR: u16 = 0x011C;
    pub const HIMR: u16 = 0x0120;
    pub const HISR: u16 = 0x0124;
    pub const HIMRE: u16 = 0x0128;
    pub const HISRE: u16 = 0x012C;
    pub const CPWM: u16 = 0x012F;
    pub const FWIMR: u16 = 0x0130;
    pub const FWISR: u16 = 0x0134;
    pub const FTIMR: u16 = 0x0138;
    pub const PKTBUF_DBG_CTRL: u16 = 0x0140;
    pub const PKTBUF_DBG_DATA_L: u16 = 0x0144;
    pub const PKTBUF_DBG_DATA_H: u16 = 0x0148;
    pub const RXPKTBUF_CTRL: u16 = 0x0284;
    pub const TXPKTBUF_CTRL: u16 = 0x0284;
    pub const C2HEVT_MSG_NORMAL: u16 = 0x01A0;
    pub const C2HEVT_CLEAR: u16 = 0x01AF;
    pub const C2HEVT_MSG_TEST: u16 = 0x01B8;
    pub const MCUTST_I: u16 = 0x01C0;
    pub const MCUTST_WOWLAN: u16 = 0x01C7;
    pub const FMETHR: u16 = 0x01C8;
    pub const HMETFR: u16 = 0x01CC;
    pub const HMEBOX_0: u16 = 0x01D0;
    pub const HMEBOX_1: u16 = 0x01D4;
    pub const HMEBOX_2: u16 = 0x01D8;
    pub const HMEBOX_3: u16 = 0x01DC;
    pub const LLT_INIT: u16 = 0x01E0;
    pub const BB_ACCESS_CTRL: u16 = 0x01E8;
    pub const BB_ACCESS_DATA: u16 = 0x01EC;
    pub const HMEBOX_EXT0_8822B: u16 = 0x01F0;
    pub const HMEBOX_EXT1_8822B: u16 = 0x01F4;
    pub const HMEBOX_EXT2_8822B: u16 = 0x01F8;
    pub const HMEBOX_EXT3_8822B: u16 = 0x01FC;
    pub const RQPN: u16 = 0x0200;
    pub const FIFOPAGE: u16 = 0x0204;
    pub const FIFOPAGE2: u16 = 0x0206;
    pub const TDECTRL: u16 = 0x0208;
    pub const TXDMA_OFFSET_CHK: u16 = 0x020C;
    pub const TXDMA_STATUS: u16 = 0x0210;
    pub const RQPN_NPQ: u16 = 0x0214;
    pub const AUTO_LLT: u16 = 0x0224;
    pub const TXPKTBUF_BCNQ_BDNY: u16 = 0x0230;
    pub const TXPKTBUF_MGQ_BDNY: u16 = 0x0231;
    pub const TXPKTBUF_WMAC_LBK_BF_HD: u16 = 0x0234;
    pub const TRXQ_CTRL: u16 = 0x0240;
    pub const RXFF_BNDY: u16 = 0x0500;
    pub const MAC_ADDR: u16 = 0x0610;
    pub const BSSID: u16 = 0x0618;
    pub const BSSIDR: u16 = 0x0700;
    pub const MACID: u16 = 0x0610;
    pub const BCN_INTERVAL: u16 = 0x0554;
    pub const TSF: u16 = 0x0560;
    pub const BCN_PSR_RPT: u16 = 0x06A8;

    /*
     * CAM (Content Addressable Memory) registers for security key storage.
     * Realtek WiFi chipsets use CAM entries to store pairwise and group keys
     * for WPA/WPA2/WPA3 encryption. Each entry can hold a 128-bit temporal key.
     */
    pub const CAMCMD: u16 = 0x0670;       // CAM command register
    pub const CAMWRITE: u16 = 0x0674;     // CAM write data register
    pub const CAMREAD: u16 = 0x0678;      // CAM read data register
    pub const CAMDBG: u16 = 0x067C;       // CAM debug register
    pub const SECCFG: u16 = 0x0680;       // Security configuration
}

pub mod bits {
    pub const SYS_FUNC_EN_CPUEN: u16 = 1 << 2;
    pub const SYS_FUNC_EN_PCIED: u16 = 1 << 6;
    pub const SYS_FUNC_EN_PPLL: u16 = 1 << 7;
    pub const SYS_FUNC_EN_BB_GLB_RST: u16 = 1 << 1;
    pub const SYS_FUNC_EN_BBRSTB: u16 = 1 << 0;

    pub const PWR_EN: u32 = 1 << 0;
    pub const CLK_EN: u32 = 1 << 1;
    pub const MAC_RST: u32 = 1 << 2;

    pub const MCUFWDL_EN: u32 = 1 << 0;
    pub const MCUFWDL_RDY: u32 = 1 << 1;
    pub const WINTINI_RDY: u32 = 1 << 6;
    pub const MAC_CLK_SEL: u32 = 1 << 7;
    pub const MAC_CLK_DIV2: u32 = 1 << 8;
    pub const CPRST: u32 = 1 << 23;
    pub const ROM_DLEN: u32 = 1 << 19;

    pub const TXDMA_INIT_VALUE: u8 = 0xFF;
    pub const RXDMA_INIT_VALUE: u8 = 0xFF;

    pub const IMR_DISABLED: u32 = 0x0;
    pub const ISR_CLEAR: u32 = 0xFFFF_FFFF;
}

pub const TX_DESC_SIZE: usize = 48;
pub const RX_DESC_SIZE: usize = 24;
pub const TX_BUFFER_SIZE: usize = 4096;
pub const RX_BUFFER_SIZE: usize = 16384;
pub const TX_RING_SIZE: usize = 256;
pub const RX_RING_SIZE: usize = 256;

pub const FIRMWARE_MAX_SIZE: usize = 512 * 1024;
pub const INIT_TIMEOUT_MS: u64 = 5000;
pub const CMD_TIMEOUT_MS: u64 = 2000;
pub const SCAN_TIMEOUT_MS: u64 = 10000;

pub const DMA_ALIGNMENT: usize = 256;
pub const DESC_ALIGNMENT: usize = 256;

pub const RSSI_INVALID: i8 = -100;

pub const FW_MAX_SIZE: usize = 512 * 1024;
pub const FW_PAGE_SIZE: usize = 4096;
pub const FW_START_ADDR: u16 = 0x1000;
