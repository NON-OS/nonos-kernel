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

#[test]
fn test_realtek_vendor_id() {
    assert_eq!(REALTEK_VENDOR_ID, 0x10EC);
}

#[test]
fn test_device_ids_not_empty() {
    assert!(!RTL8139_DEVICE_IDS.is_empty());
}

#[test]
fn test_device_id_rtl8139() {
    assert!(RTL8139_DEVICE_IDS.contains(&0x8139));
}

#[test]
fn test_device_id_rtl8138() {
    assert!(RTL8139_DEVICE_IDS.contains(&0x8138));
}

#[test]
fn test_device_id_rtl8129() {
    assert!(RTL8139_DEVICE_IDS.contains(&0x8129));
}

#[test]
fn test_device_id_rtl8131() {
    assert!(RTL8139_DEVICE_IDS.contains(&0x8131));
}

#[test]
fn test_device_id_rtl8136() {
    assert!(RTL8139_DEVICE_IDS.contains(&0x8136));
}

#[test]
fn test_device_id_rtl8100() {
    assert!(RTL8139_DEVICE_IDS.contains(&0x8100));
}

#[test]
fn test_reg_idr0() {
    assert_eq!(reg::IDR0, 0x00);
}

#[test]
fn test_reg_idr4() {
    assert_eq!(reg::IDR4, 0x04);
}

#[test]
fn test_reg_mar0() {
    assert_eq!(reg::MAR0, 0x08);
}

#[test]
fn test_reg_mar4() {
    assert_eq!(reg::MAR4, 0x0C);
}

#[test]
fn test_reg_tsd0() {
    assert_eq!(reg::TSD0, 0x10);
}

#[test]
fn test_reg_tsd1() {
    assert_eq!(reg::TSD1, 0x14);
}

#[test]
fn test_reg_tsd2() {
    assert_eq!(reg::TSD2, 0x18);
}

#[test]
fn test_reg_tsd3() {
    assert_eq!(reg::TSD3, 0x1C);
}

#[test]
fn test_reg_tsad0() {
    assert_eq!(reg::TSAD0, 0x20);
}

#[test]
fn test_reg_tsad1() {
    assert_eq!(reg::TSAD1, 0x24);
}

#[test]
fn test_reg_tsad2() {
    assert_eq!(reg::TSAD2, 0x28);
}

#[test]
fn test_reg_tsad3() {
    assert_eq!(reg::TSAD3, 0x2C);
}

#[test]
fn test_reg_rbstart() {
    assert_eq!(reg::RBSTART, 0x30);
}

#[test]
fn test_reg_cr() {
    assert_eq!(reg::CR, 0x37);
}

#[test]
fn test_reg_capr() {
    assert_eq!(reg::CAPR, 0x38);
}

#[test]
fn test_reg_cbr() {
    assert_eq!(reg::CBR, 0x3A);
}

#[test]
fn test_reg_imr() {
    assert_eq!(reg::IMR, 0x3C);
}

#[test]
fn test_reg_isr() {
    assert_eq!(reg::ISR, 0x3E);
}

#[test]
fn test_reg_tcr() {
    assert_eq!(reg::TCR, 0x40);
}

#[test]
fn test_reg_rcr() {
    assert_eq!(reg::RCR, 0x44);
}

#[test]
fn test_reg_msr() {
    assert_eq!(reg::MSR, 0x58);
}

#[test]
fn test_reg_bmcr() {
    assert_eq!(reg::BMCR, 0x62);
}

#[test]
fn test_reg_bmsr() {
    assert_eq!(reg::BMSR, 0x64);
}

#[test]
fn test_cmd_bufe() {
    assert_eq!(cmd::BUFE, 1 << 0);
}

#[test]
fn test_cmd_te() {
    assert_eq!(cmd::TE, 1 << 2);
}

#[test]
fn test_cmd_re() {
    assert_eq!(cmd::RE, 1 << 3);
}

#[test]
fn test_cmd_rst() {
    assert_eq!(cmd::RST, 1 << 4);
}

#[test]
fn test_rcr_aap() {
    assert_eq!(rcr::AAP, 1 << 0);
}

#[test]
fn test_rcr_apm() {
    assert_eq!(rcr::APM, 1 << 1);
}

#[test]
fn test_rcr_am() {
    assert_eq!(rcr::AM, 1 << 2);
}

#[test]
fn test_rcr_ab() {
    assert_eq!(rcr::AB, 1 << 3);
}

#[test]
fn test_rcr_ar() {
    assert_eq!(rcr::AR, 1 << 4);
}

#[test]
fn test_rcr_aer() {
    assert_eq!(rcr::AER, 1 << 5);
}

#[test]
fn test_rcr_wrap() {
    assert_eq!(rcr::WRAP, 1 << 7);
}

#[test]
fn test_rcr_rblen_8k() {
    assert_eq!(rcr::RBLEN_8K, 0 << 11);
}

#[test]
fn test_rcr_rblen_16k() {
    assert_eq!(rcr::RBLEN_16K, 1 << 11);
}

#[test]
fn test_rcr_rblen_32k() {
    assert_eq!(rcr::RBLEN_32K, 2 << 11);
}

#[test]
fn test_rcr_rblen_64k() {
    assert_eq!(rcr::RBLEN_64K, 3 << 11);
}

#[test]
fn test_tcr_clrabt() {
    assert_eq!(tcr::CLRABT, 1 << 0);
}

#[test]
fn test_tcr_mxdma_16() {
    assert_eq!(tcr::MXDMA_16, 0 << 8);
}

#[test]
fn test_tcr_mxdma_32() {
    assert_eq!(tcr::MXDMA_32, 1 << 8);
}

#[test]
fn test_tcr_mxdma_64() {
    assert_eq!(tcr::MXDMA_64, 2 << 8);
}

#[test]
fn test_tcr_mxdma_128() {
    assert_eq!(tcr::MXDMA_128, 3 << 8);
}

#[test]
fn test_tcr_mxdma_256() {
    assert_eq!(tcr::MXDMA_256, 4 << 8);
}

#[test]
fn test_tcr_mxdma_512() {
    assert_eq!(tcr::MXDMA_512, 5 << 8);
}

#[test]
fn test_tcr_mxdma_1024() {
    assert_eq!(tcr::MXDMA_1024, 6 << 8);
}

#[test]
fn test_tcr_mxdma_unlim() {
    assert_eq!(tcr::MXDMA_UNLIM, 7 << 8);
}

#[test]
fn test_tcr_ifg_std() {
    assert_eq!(tcr::IFG_STD, 3 << 24);
}

#[test]
fn test_tsd_own() {
    assert_eq!(tsd::OWN, 1 << 13);
}

#[test]
fn test_tsd_tun() {
    assert_eq!(tsd::TUN, 1 << 14);
}

#[test]
fn test_tsd_tok() {
    assert_eq!(tsd::TOK, 1 << 15);
}

#[test]
fn test_int_rok() {
    assert_eq!(int::ROK, 1 << 0);
}

#[test]
fn test_int_rer() {
    assert_eq!(int::RER, 1 << 1);
}

#[test]
fn test_int_tok() {
    assert_eq!(int::TOK, 1 << 2);
}

#[test]
fn test_int_ter() {
    assert_eq!(int::TER, 1 << 3);
}

#[test]
fn test_int_rxovw() {
    assert_eq!(int::RXOVW, 1 << 4);
}

#[test]
fn test_int_pun() {
    assert_eq!(int::PUN, 1 << 5);
}

#[test]
fn test_int_fovw() {
    assert_eq!(int::FOVW, 1 << 6);
}

#[test]
fn test_int_timeout() {
    assert_eq!(int::TIMEOUT, 1 << 14);
}

#[test]
fn test_int_serr() {
    assert_eq!(int::SERR, 1 << 15);
}

#[test]
fn test_msr_rxpf() {
    assert_eq!(msr::RXPF, 1 << 0);
}

#[test]
fn test_msr_txpf() {
    assert_eq!(msr::TXPF, 1 << 1);
}

#[test]
fn test_msr_linkb() {
    assert_eq!(msr::LINKB, 1 << 2);
}

#[test]
fn test_msr_speed10() {
    assert_eq!(msr::SPEED10, 1 << 3);
}

#[test]
fn test_msr_auxsts() {
    assert_eq!(msr::AUXSTS, 1 << 4);
}

#[test]
fn test_msr_rxfce() {
    assert_eq!(msr::RXFCE, 1 << 6);
}

#[test]
fn test_msr_txfce() {
    assert_eq!(msr::TXFCE, 1 << 7);
}

#[test]
fn test_rx_buffer_size() {
    assert_eq!(RX_BUFFER_SIZE, 8192 + 16 + 1500);
}

#[test]
fn test_tx_desc_count() {
    assert_eq!(TX_DESC_COUNT, 4);
}

#[test]
fn test_tx_buffer_size() {
    assert_eq!(TX_BUFFER_SIZE, 1536);
}

#[test]
fn test_min_frame_size() {
    assert_eq!(MIN_FRAME_SIZE, 14);
}

#[test]
fn test_max_mtu() {
    assert_eq!(MAX_MTU, 1500);
}

#[test]
fn test_tx_buffer_larger_than_mtu() {
    assert!(TX_BUFFER_SIZE > MAX_MTU);
}

#[test]
fn test_rx_buffer_larger_than_8k() {
    assert!(RX_BUFFER_SIZE > 8192);
}

#[test]
fn test_tsd_registers_spacing() {
    assert_eq!(reg::TSD1 - reg::TSD0, 4);
    assert_eq!(reg::TSD2 - reg::TSD1, 4);
    assert_eq!(reg::TSD3 - reg::TSD2, 4);
}

#[test]
fn test_tsad_registers_spacing() {
    assert_eq!(reg::TSAD1 - reg::TSAD0, 4);
    assert_eq!(reg::TSAD2 - reg::TSAD1, 4);
    assert_eq!(reg::TSAD3 - reg::TSAD2, 4);
}
