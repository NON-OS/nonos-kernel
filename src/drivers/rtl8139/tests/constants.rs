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

use crate::drivers::rtl8139::constants::*;
use crate::test::framework::TestResult;

pub(crate) fn test_realtek_vendor_id() -> TestResult {
    if REALTEK_VENDOR_ID != 0x10EC {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_ids_not_empty() -> TestResult {
    if RTL8139_DEVICE_IDS.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_id_rtl8139() -> TestResult {
    if !RTL8139_DEVICE_IDS.contains(&0x8139) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_id_rtl8138() -> TestResult {
    if !RTL8139_DEVICE_IDS.contains(&0x8138) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_id_rtl8129() -> TestResult {
    if !RTL8139_DEVICE_IDS.contains(&0x8129) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_id_rtl8131() -> TestResult {
    if !RTL8139_DEVICE_IDS.contains(&0x8131) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_id_rtl8136() -> TestResult {
    if !RTL8139_DEVICE_IDS.contains(&0x8136) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_id_rtl8100() -> TestResult {
    if !RTL8139_DEVICE_IDS.contains(&0x8100) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_idr0() -> TestResult {
    if reg::IDR0 != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_idr4() -> TestResult {
    if reg::IDR4 != 0x04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_mar0() -> TestResult {
    if reg::MAR0 != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_mar4() -> TestResult {
    if reg::MAR4 != 0x0C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_tsd0() -> TestResult {
    if reg::TSD0 != 0x10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_tsd1() -> TestResult {
    if reg::TSD1 != 0x14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_tsd2() -> TestResult {
    if reg::TSD2 != 0x18 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_tsd3() -> TestResult {
    if reg::TSD3 != 0x1C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_tsad0() -> TestResult {
    if reg::TSAD0 != 0x20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_tsad1() -> TestResult {
    if reg::TSAD1 != 0x24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_tsad2() -> TestResult {
    if reg::TSAD2 != 0x28 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_tsad3() -> TestResult {
    if reg::TSAD3 != 0x2C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_rbstart() -> TestResult {
    if reg::RBSTART != 0x30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_cr() -> TestResult {
    if reg::CR != 0x37 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_capr() -> TestResult {
    if reg::CAPR != 0x38 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_cbr() -> TestResult {
    if reg::CBR != 0x3A {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_imr() -> TestResult {
    if reg::IMR != 0x3C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_isr() -> TestResult {
    if reg::ISR != 0x3E {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_tcr() -> TestResult {
    if reg::TCR != 0x40 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_rcr() -> TestResult {
    if reg::RCR != 0x44 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_msr() -> TestResult {
    if reg::MSR != 0x58 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_bmcr() -> TestResult {
    if reg::BMCR != 0x62 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_bmsr() -> TestResult {
    if reg::BMSR != 0x64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cmd_bufe() -> TestResult {
    if cmd::BUFE != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cmd_te() -> TestResult {
    if cmd::TE != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cmd_re() -> TestResult {
    if cmd::RE != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cmd_rst() -> TestResult {
    if cmd::RST != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rcr_aap() -> TestResult {
    if rcr::AAP != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rcr_apm() -> TestResult {
    if rcr::APM != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rcr_am() -> TestResult {
    if rcr::AM != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rcr_ab() -> TestResult {
    if rcr::AB != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rcr_ar() -> TestResult {
    if rcr::AR != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rcr_aer() -> TestResult {
    if rcr::AER != 1 << 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rcr_wrap() -> TestResult {
    if rcr::WRAP != 1 << 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rcr_rblen_8k() -> TestResult {
    if rcr::RBLEN_8K != 0 << 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rcr_rblen_16k() -> TestResult {
    if rcr::RBLEN_16K != 1 << 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rcr_rblen_32k() -> TestResult {
    if rcr::RBLEN_32K != 2 << 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rcr_rblen_64k() -> TestResult {
    if rcr::RBLEN_64K != 3 << 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcr_clrabt() -> TestResult {
    if tcr::CLRABT != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcr_mxdma_16() -> TestResult {
    if tcr::MXDMA_16 != 0 << 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcr_mxdma_32() -> TestResult {
    if tcr::MXDMA_32 != 1 << 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcr_mxdma_64() -> TestResult {
    if tcr::MXDMA_64 != 2 << 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcr_mxdma_128() -> TestResult {
    if tcr::MXDMA_128 != 3 << 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcr_mxdma_256() -> TestResult {
    if tcr::MXDMA_256 != 4 << 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcr_mxdma_512() -> TestResult {
    if tcr::MXDMA_512 != 5 << 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcr_mxdma_1024() -> TestResult {
    if tcr::MXDMA_1024 != 6 << 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcr_mxdma_unlim() -> TestResult {
    if tcr::MXDMA_UNLIM != 7 << 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcr_ifg_std() -> TestResult {
    if tcr::IFG_STD != 3 << 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tsd_own() -> TestResult {
    if tsd::OWN != 1 << 13 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tsd_tun() -> TestResult {
    if tsd::TUN != 1 << 14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tsd_tok() -> TestResult {
    if tsd::TOK != 1 << 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_rok() -> TestResult {
    if int::ROK != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_rer() -> TestResult {
    if int::RER != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_tok() -> TestResult {
    if int::TOK != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_ter() -> TestResult {
    if int::TER != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_rxovw() -> TestResult {
    if int::RXOVW != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_pun() -> TestResult {
    if int::PUN != 1 << 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_fovw() -> TestResult {
    if int::FOVW != 1 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_timeout() -> TestResult {
    if int::TIMEOUT != 1 << 14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_serr() -> TestResult {
    if int::SERR != 1 << 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_msr_rxpf() -> TestResult {
    if msr::RXPF != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_msr_txpf() -> TestResult {
    if msr::TXPF != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_msr_linkb() -> TestResult {
    if msr::LINKB != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_msr_speed10() -> TestResult {
    if msr::SPEED10 != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_msr_auxsts() -> TestResult {
    if msr::AUXSTS != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_msr_rxfce() -> TestResult {
    if msr::RXFCE != 1 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_msr_txfce() -> TestResult {
    if msr::TXFCE != 1 << 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_buffer_size() -> TestResult {
    if RX_BUFFER_SIZE != 8192 + 16 + 1500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_count() -> TestResult {
    if TX_DESC_COUNT != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_buffer_size() -> TestResult {
    if TX_BUFFER_SIZE != 1536 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_min_frame_size() -> TestResult {
    if MIN_FRAME_SIZE != 14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_mtu() -> TestResult {
    if MAX_MTU != 1500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_buffer_larger_than_mtu() -> TestResult {
    if !(TX_BUFFER_SIZE > MAX_MTU) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_buffer_larger_than_8k() -> TestResult {
    if !(RX_BUFFER_SIZE > 8192) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tsd_registers_spacing() -> TestResult {
    if reg::TSD1 - reg::TSD0 != 4 {
        return TestResult::Fail;
    }
    if reg::TSD2 - reg::TSD1 != 4 {
        return TestResult::Fail;
    }
    if reg::TSD3 - reg::TSD2 != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tsad_registers_spacing() -> TestResult {
    if reg::TSAD1 - reg::TSAD0 != 4 {
        return TestResult::Fail;
    }
    if reg::TSAD2 - reg::TSAD1 != 4 {
        return TestResult::Fail;
    }
    if reg::TSAD3 - reg::TSAD2 != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
