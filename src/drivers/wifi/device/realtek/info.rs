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

use super::super::super::error::WifiError;
use super::constants::*;
use super::core::RealtekWifiDevice;

impl RealtekWifiDevice {
    pub fn get_hardware_info(&self) -> RealtekHardwareInfo {
        RealtekHardwareInfo {
            device_id: self.device_id,
            sys_clk: self.read32(regs::SYS_CLK),
            sys_iso_ctrl: self.read16(regs::SYS_ISO_CTRL),
            sys_pwr_ctrl: self.read32(regs::SYS_PWR_CTRL),
            afe_misc: self.read32(regs::AFE_MISC),
            afe_pll_ctrl: self.read32(regs::AFE_PLL_CTRL),
            efuse_ctrl: self.read32(regs::EFUSE_CTRL),
            efuse_test: self.read32(regs::EFUSE_TEST),
            gpio_muxcfg: self.read16(regs::GPIO_MUXCFG),
            gpio_io_sel: self.read16(regs::GPIO_IO_SEL),
            gpio_pin_ctrl: self.read32(regs::GPIO_PIN_CTRL),
            gpio_intm: self.read32(regs::GPIO_INTM),
            led_cfg: [
                self.read8(regs::LEDCFG0),
                self.read8(regs::LEDCFG1),
                self.read8(regs::LEDCFG2),
            ],
            mcu_fwdl: self.read32(regs::MCUFWDL),
            hmebox_ext: [
                self.read16(regs::HMEBOX_EXT_0),
                self.read16(regs::HMEBOX_EXT_1),
                self.read16(regs::HMEBOX_EXT_2),
                self.read16(regs::HMEBOX_EXT_3),
            ],
            bist_scan: self.read32(regs::BIST_SCAN),
            wlan_info: self.read32(regs::WLAN_INFO),
            pbp: self.read32(regs::PBP),
            pkt_buff_access_ctrl: self.read16(regs::PKT_BUFF_ACCESS_CTRL),
            trxff_bndy: self.read16(regs::TRXFF_BNDY),
            trxff_status: self.read32(regs::TRXFF_STATUS),
            rxff_ptr: self.read32(regs::RXFF_PTR),
            cpwm: self.read8(regs::CPWM),
            fw_imr: self.read32(regs::FWIMR),
            fw_isr: self.read32(regs::FWISR),
            ft_imr: self.read32(regs::FTIMR),
            pktbuf_dbg_ctrl: self.read32(regs::PKTBUF_DBG_CTRL),
            pktbuf_dbg_data: [
                self.read32(regs::PKTBUF_DBG_DATA_L),
                self.read32(regs::PKTBUF_DBG_DATA_H),
            ],
            rxpktbuf_ctrl: self.read32(regs::RXPKTBUF_CTRL),
            txpktbuf_ctrl: self.read32(regs::TXPKTBUF_CTRL),
            c2h_evt_msg: self.read32(regs::C2HEVT_MSG_NORMAL),
            c2h_evt_clear: self.read8(regs::C2HEVT_CLEAR),
            c2h_evt_test: self.read32(regs::C2HEVT_MSG_TEST),
            mcu_tst: [
                self.read32(regs::MCUTST_I),
                self.read8(regs::MCUTST_WOWLAN) as u32,
            ],
            fmethr: self.read32(regs::FMETHR),
            hmetfr: self.read32(regs::HMETFR),
            hmebox: [
                self.read32(regs::HMEBOX_0),
                self.read32(regs::HMEBOX_1),
                self.read32(regs::HMEBOX_2),
                self.read32(regs::HMEBOX_3),
            ],
            llt_init: self.read32(regs::LLT_INIT),
            bb_access_ctrl: self.read32(regs::BB_ACCESS_CTRL),
            bb_access_data: self.read32(regs::BB_ACCESS_DATA),
            hmebox_ext_8822b: [
                self.read32(regs::HMEBOX_EXT0_8822B),
                self.read32(regs::HMEBOX_EXT1_8822B),
                self.read32(regs::HMEBOX_EXT2_8822B),
                self.read32(regs::HMEBOX_EXT3_8822B),
            ],
            rqpn: self.read32(regs::RQPN),
            fifopage: [
                self.read16(regs::FIFOPAGE),
                self.read16(regs::FIFOPAGE2),
            ],
            tdectrl: self.read32(regs::TDECTRL),
            txdma_offset_chk: self.read32(regs::TXDMA_OFFSET_CHK),
            txdma_status: self.read32(regs::TXDMA_STATUS),
            rqpn_npq: self.read32(regs::RQPN_NPQ),
            auto_llt: self.read32(regs::AUTO_LLT),
            txpktbuf_bcnq_bdny: self.read8(regs::TXPKTBUF_BCNQ_BDNY),
            txpktbuf_mgq_bdny: self.read8(regs::TXPKTBUF_MGQ_BDNY),
            txpktbuf_wmac_lbk_bf_hd: self.read32(regs::TXPKTBUF_WMAC_LBK_BF_HD),
        }
    }

    pub fn get_dma_config(&self) -> RealtekDmaConfig {
        RealtekDmaConfig {
            tx_desc_size: TX_DESC_SIZE,
            rx_desc_size: RX_DESC_SIZE,
            tx_buffer_size: TX_BUFFER_SIZE,
            rx_buffer_size: RX_BUFFER_SIZE,
            tx_ring_size: TX_RING_SIZE,
            rx_ring_size: RX_RING_SIZE,
            firmware_max_size: FIRMWARE_MAX_SIZE,
            init_timeout_ms: INIT_TIMEOUT_MS,
            cmd_timeout_ms: CMD_TIMEOUT_MS,
            scan_timeout_ms: SCAN_TIMEOUT_MS,
            dma_alignment: DMA_ALIGNMENT,
            desc_alignment: DESC_ALIGNMENT,
            tx_ring_phys: self.tx_ring_phys.as_u64(),
            rx_ring_phys: self.rx_ring_phys.as_u64(),
        }
    }

    pub fn get_security_type(&self) -> super::super::super::scan::SecurityType {
        self.current_security
    }

    pub fn upload_firmware_section(&mut self, offset: u32, data: &[u8]) -> Result<(), WifiError> {
        if data.len() > FIRMWARE_MAX_SIZE {
            return Err(WifiError::FirmwareInvalid);
        }

        let mcu_fwdl = self.read32(regs::MCUFWDL);
        self.write32(regs::MCUFWDL, mcu_fwdl | bits::MCUFWDL_EN);

        for (i, chunk) in data.chunks(4).enumerate() {
            let val = if chunk.len() == 4 {
                u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
            } else {
                let mut buf = [0u8; 4];
                buf[..chunk.len()].copy_from_slice(chunk);
                u32::from_le_bytes(buf)
            };

            let addr = offset + (i as u32 * 4);
            self.write32(regs::FMETHR, addr);
            self.write32(regs::HMETFR, val);
        }

        self.write32(regs::MCUFWDL, mcu_fwdl & !bits::MCUFWDL_EN);
        Ok(())
    }

    pub fn wait_firmware_ready(&self) -> Result<(), WifiError> {
        let start = crate::arch::x86_64::time::tsc::elapsed_us();
        while crate::arch::x86_64::time::tsc::elapsed_us() - start < (INIT_TIMEOUT_MS * 1000) {
            let status = self.read32(regs::MCUFWDL);
            if (status & bits::WINTINI_RDY) != 0 {
                return Ok(());
            }
            self.delay_us(100);
        }
        Err(WifiError::HardwareError)
    }
}

#[derive(Clone, Debug)]
pub struct RealtekHardwareInfo {
    pub device_id: u16,
    pub sys_clk: u32,
    pub sys_iso_ctrl: u16,
    pub sys_pwr_ctrl: u32,
    pub afe_misc: u32,
    pub afe_pll_ctrl: u32,
    pub efuse_ctrl: u32,
    pub efuse_test: u32,
    pub gpio_muxcfg: u16,
    pub gpio_io_sel: u16,
    pub gpio_pin_ctrl: u32,
    pub gpio_intm: u32,
    pub led_cfg: [u8; 3],
    pub mcu_fwdl: u32,
    pub hmebox_ext: [u16; 4],
    pub bist_scan: u32,
    pub wlan_info: u32,
    pub pbp: u32,
    pub pkt_buff_access_ctrl: u16,
    pub trxff_bndy: u16,
    pub trxff_status: u32,
    pub rxff_ptr: u32,
    pub cpwm: u8,
    pub fw_imr: u32,
    pub fw_isr: u32,
    pub ft_imr: u32,
    pub pktbuf_dbg_ctrl: u32,
    pub pktbuf_dbg_data: [u32; 2],
    pub rxpktbuf_ctrl: u32,
    pub txpktbuf_ctrl: u32,
    pub c2h_evt_msg: u32,
    pub c2h_evt_clear: u8,
    pub c2h_evt_test: u32,
    pub mcu_tst: [u32; 2],
    pub fmethr: u32,
    pub hmetfr: u32,
    pub hmebox: [u32; 4],
    pub llt_init: u32,
    pub bb_access_ctrl: u32,
    pub bb_access_data: u32,
    pub hmebox_ext_8822b: [u32; 4],
    pub rqpn: u32,
    pub fifopage: [u16; 2],
    pub tdectrl: u32,
    pub txdma_offset_chk: u32,
    pub txdma_status: u32,
    pub rqpn_npq: u32,
    pub auto_llt: u32,
    pub txpktbuf_bcnq_bdny: u8,
    pub txpktbuf_mgq_bdny: u8,
    pub txpktbuf_wmac_lbk_bf_hd: u32,
}

#[derive(Clone, Debug)]
pub struct RealtekDmaConfig {
    pub tx_desc_size: usize,
    pub rx_desc_size: usize,
    pub tx_buffer_size: usize,
    pub rx_buffer_size: usize,
    pub tx_ring_size: usize,
    pub rx_ring_size: usize,
    pub firmware_max_size: usize,
    pub init_timeout_ms: u64,
    pub cmd_timeout_ms: u64,
    pub scan_timeout_ms: u64,
    pub dma_alignment: usize,
    pub desc_alignment: usize,
    pub tx_ring_phys: u64,
    pub rx_ring_phys: u64,
}
