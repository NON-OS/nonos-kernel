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

use crate::drivers::e1000::constants::*;

#[test]
fn test_intel_vendor_id() {
    assert_eq!(INTEL_VENDOR_ID, 0x8086);
}

#[test]
fn test_device_ids_not_empty() {
    assert!(!E1000_DEVICE_IDS.is_empty());
}

#[test]
fn test_device_id_classic_100e() {
    assert!(E1000_DEVICE_IDS.contains(&0x100E));
}

#[test]
fn test_device_id_classic_100f() {
    assert!(E1000_DEVICE_IDS.contains(&0x100F));
}

#[test]
fn test_device_id_i210() {
    assert!(E1000_DEVICE_IDS.contains(&0x1533));
}

#[test]
fn test_device_id_i219() {
    assert!(E1000_DEVICE_IDS.contains(&0x15B7));
}

#[test]
fn test_device_id_i350() {
    assert!(E1000_DEVICE_IDS.contains(&0x1521));
}

#[test]
fn test_reg_ctrl() {
    assert_eq!(reg::CTRL, 0x0000);
}

#[test]
fn test_reg_status() {
    assert_eq!(reg::STATUS, 0x0008);
}

#[test]
fn test_reg_eecd() {
    assert_eq!(reg::EECD, 0x0010);
}

#[test]
fn test_reg_eerd() {
    assert_eq!(reg::EERD, 0x0014);
}

#[test]
fn test_reg_icr() {
    assert_eq!(reg::ICR, 0x00C0);
}

#[test]
fn test_reg_itr() {
    assert_eq!(reg::ITR, 0x00C4);
}

#[test]
fn test_reg_ics() {
    assert_eq!(reg::ICS, 0x00C8);
}

#[test]
fn test_reg_ims() {
    assert_eq!(reg::IMS, 0x00D0);
}

#[test]
fn test_reg_imc() {
    assert_eq!(reg::IMC, 0x00D8);
}

#[test]
fn test_reg_rctl() {
    assert_eq!(reg::RCTL, 0x0100);
}

#[test]
fn test_reg_tctl() {
    assert_eq!(reg::TCTL, 0x0400);
}

#[test]
fn test_reg_tipg() {
    assert_eq!(reg::TIPG, 0x0410);
}

#[test]
fn test_reg_rdbal() {
    assert_eq!(reg::RDBAL, 0x2800);
}

#[test]
fn test_reg_rdbah() {
    assert_eq!(reg::RDBAH, 0x2804);
}

#[test]
fn test_reg_rdlen() {
    assert_eq!(reg::RDLEN, 0x2808);
}

#[test]
fn test_reg_rdh() {
    assert_eq!(reg::RDH, 0x2810);
}

#[test]
fn test_reg_rdt() {
    assert_eq!(reg::RDT, 0x2818);
}

#[test]
fn test_reg_tdbal() {
    assert_eq!(reg::TDBAL, 0x3800);
}

#[test]
fn test_reg_tdbah() {
    assert_eq!(reg::TDBAH, 0x3804);
}

#[test]
fn test_reg_tdlen() {
    assert_eq!(reg::TDLEN, 0x3808);
}

#[test]
fn test_reg_tdh() {
    assert_eq!(reg::TDH, 0x3810);
}

#[test]
fn test_reg_tdt() {
    assert_eq!(reg::TDT, 0x3818);
}

#[test]
fn test_reg_ral0() {
    assert_eq!(reg::RAL0, 0x5400);
}

#[test]
fn test_reg_rah0() {
    assert_eq!(reg::RAH0, 0x5404);
}

#[test]
fn test_reg_mta() {
    assert_eq!(reg::MTA, 0x5200);
}

#[test]
fn test_ctrl_fd() {
    assert_eq!(ctrl::FD, 1 << 0);
}

#[test]
fn test_ctrl_lrst() {
    assert_eq!(ctrl::LRST, 1 << 3);
}

#[test]
fn test_ctrl_asde() {
    assert_eq!(ctrl::ASDE, 1 << 5);
}

#[test]
fn test_ctrl_slu() {
    assert_eq!(ctrl::SLU, 1 << 6);
}

#[test]
fn test_ctrl_ilos() {
    assert_eq!(ctrl::ILOS, 1 << 7);
}

#[test]
fn test_ctrl_rst() {
    assert_eq!(ctrl::RST, 1 << 26);
}

#[test]
fn test_ctrl_vme() {
    assert_eq!(ctrl::VME, 1 << 30);
}

#[test]
fn test_ctrl_phy_rst() {
    assert_eq!(ctrl::PHY_RST, 1u32 << 31);
}

#[test]
fn test_status_fd() {
    assert_eq!(status::FD, 1 << 0);
}

#[test]
fn test_status_lu() {
    assert_eq!(status::LU, 1 << 1);
}

#[test]
fn test_status_txoff() {
    assert_eq!(status::TXOFF, 1 << 4);
}

#[test]
fn test_status_speed_mask() {
    assert_eq!(status::SPEED_MASK, 3 << 6);
}

#[test]
fn test_status_speed_10() {
    assert_eq!(status::SPEED_10, 0 << 6);
}

#[test]
fn test_status_speed_100() {
    assert_eq!(status::SPEED_100, 1 << 6);
}

#[test]
fn test_status_speed_1000() {
    assert_eq!(status::SPEED_1000, 2 << 6);
}

#[test]
fn test_rctl_en() {
    assert_eq!(rctl::EN, 1 << 1);
}

#[test]
fn test_rctl_sbp() {
    assert_eq!(rctl::SBP, 1 << 2);
}

#[test]
fn test_rctl_upe() {
    assert_eq!(rctl::UPE, 1 << 3);
}

#[test]
fn test_rctl_mpe() {
    assert_eq!(rctl::MPE, 1 << 4);
}

#[test]
fn test_rctl_lpe() {
    assert_eq!(rctl::LPE, 1 << 5);
}

#[test]
fn test_rctl_lbm_none() {
    assert_eq!(rctl::LBM_NONE, 0 << 6);
}

#[test]
fn test_rctl_rdmts_half() {
    assert_eq!(rctl::RDMTS_HALF, 0 << 8);
}

#[test]
fn test_rctl_bam() {
    assert_eq!(rctl::BAM, 1 << 15);
}

#[test]
fn test_rctl_bsize_2048() {
    assert_eq!(rctl::BSIZE_2048, 0 << 16);
}

#[test]
fn test_rctl_bsize_1024() {
    assert_eq!(rctl::BSIZE_1024, 1 << 16);
}

#[test]
fn test_rctl_bsize_512() {
    assert_eq!(rctl::BSIZE_512, 2 << 16);
}

#[test]
fn test_rctl_bsize_256() {
    assert_eq!(rctl::BSIZE_256, 3 << 16);
}

#[test]
fn test_rctl_secrc() {
    assert_eq!(rctl::SECRC, 1 << 26);
}

#[test]
fn test_tctl_en() {
    assert_eq!(tctl::EN, 1 << 1);
}

#[test]
fn test_tctl_psp() {
    assert_eq!(tctl::PSP, 1 << 3);
}

#[test]
fn test_tctl_ct_shift() {
    assert_eq!(tctl::CT_SHIFT, 4);
}

#[test]
fn test_tctl_cold_shift() {
    assert_eq!(tctl::COLD_SHIFT, 12);
}

#[test]
fn test_tctl_swxoff() {
    assert_eq!(tctl::SWXOFF, 1 << 22);
}

#[test]
fn test_tctl_rtlc() {
    assert_eq!(tctl::RTLC, 1 << 24);
}

#[test]
fn test_int_txdw() {
    assert_eq!(int::TXDW, 1 << 0);
}

#[test]
fn test_int_txqe() {
    assert_eq!(int::TXQE, 1 << 1);
}

#[test]
fn test_int_lsc() {
    assert_eq!(int::LSC, 1 << 2);
}

#[test]
fn test_int_rxseq() {
    assert_eq!(int::RXSEQ, 1 << 3);
}

#[test]
fn test_int_rxdmt0() {
    assert_eq!(int::RXDMT0, 1 << 4);
}

#[test]
fn test_int_rxo() {
    assert_eq!(int::RXO, 1 << 6);
}

#[test]
fn test_int_rxt0() {
    assert_eq!(int::RXT0, 1 << 7);
}

#[test]
fn test_tx_cmd_eop() {
    assert_eq!(tx_cmd::EOP, 1 << 0);
}

#[test]
fn test_tx_cmd_ifcs() {
    assert_eq!(tx_cmd::IFCS, 1 << 1);
}

#[test]
fn test_tx_cmd_ic() {
    assert_eq!(tx_cmd::IC, 1 << 2);
}

#[test]
fn test_tx_cmd_rs() {
    assert_eq!(tx_cmd::RS, 1 << 3);
}

#[test]
fn test_tx_cmd_rps() {
    assert_eq!(tx_cmd::RPS, 1 << 4);
}

#[test]
fn test_tx_cmd_dext() {
    assert_eq!(tx_cmd::DEXT, 1 << 5);
}

#[test]
fn test_tx_cmd_vle() {
    assert_eq!(tx_cmd::VLE, 1 << 6);
}

#[test]
fn test_tx_cmd_ide() {
    assert_eq!(tx_cmd::IDE, 1 << 7);
}

#[test]
fn test_rx_desc_count() {
    assert_eq!(RX_DESC_COUNT, 32);
}

#[test]
fn test_tx_desc_count() {
    assert_eq!(TX_DESC_COUNT, 32);
}

#[test]
fn test_buffer_size() {
    assert_eq!(BUFFER_SIZE, 2048);
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
fn test_desc_alignment() {
    assert_eq!(DESC_ALIGNMENT, 128);
}

#[test]
fn test_default_tipg() {
    assert_eq!(DEFAULT_TIPG, 0x0060200A);
}

#[test]
fn test_default_collision_threshold() {
    assert_eq!(DEFAULT_COLLISION_THRESHOLD, 15);
}

#[test]
fn test_default_collision_distance() {
    assert_eq!(DEFAULT_COLLISION_DISTANCE, 64);
}

#[test]
fn test_buffer_size_larger_than_mtu() {
    assert!(BUFFER_SIZE > MAX_MTU);
}

#[test]
fn test_desc_count_power_of_two() {
    assert!(RX_DESC_COUNT.is_power_of_two());
    assert!(TX_DESC_COUNT.is_power_of_two());
}

#[test]
fn test_rx_tx_ring_spacing() {
    assert_eq!(reg::RDBAH - reg::RDBAL, 4);
    assert_eq!(reg::TDBAH - reg::TDBAL, 4);
}
