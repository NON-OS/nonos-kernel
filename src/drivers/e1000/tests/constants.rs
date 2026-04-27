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
use crate::test::framework::TestResult;

pub(crate) fn test_intel_vendor_id() -> TestResult {
    if INTEL_VENDOR_ID != 0x8086 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_ids_not_empty() -> TestResult {
    if E1000_DEVICE_IDS.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_id_classic_100e() -> TestResult {
    if !E1000_DEVICE_IDS.contains(&0x100E) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_id_classic_100f() -> TestResult {
    if !E1000_DEVICE_IDS.contains(&0x100F) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_id_i210() -> TestResult {
    if !E1000_DEVICE_IDS.contains(&0x1533) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_id_i219() -> TestResult {
    if !E1000_DEVICE_IDS.contains(&0x15B7) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_id_i350() -> TestResult {
    if !E1000_DEVICE_IDS.contains(&0x1521) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_ctrl() -> TestResult {
    if reg::CTRL != 0x0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_status() -> TestResult {
    if reg::STATUS != 0x0008 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_eecd() -> TestResult {
    if reg::EECD != 0x0010 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_eerd() -> TestResult {
    if reg::EERD != 0x0014 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_icr() -> TestResult {
    if reg::ICR != 0x00C0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_itr() -> TestResult {
    if reg::ITR != 0x00C4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_ics() -> TestResult {
    if reg::ICS != 0x00C8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_ims() -> TestResult {
    if reg::IMS != 0x00D0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_imc() -> TestResult {
    if reg::IMC != 0x00D8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_rctl() -> TestResult {
    if reg::RCTL != 0x0100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_tctl() -> TestResult {
    if reg::TCTL != 0x0400 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_tipg() -> TestResult {
    if reg::TIPG != 0x0410 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_rdbal() -> TestResult {
    if reg::RDBAL != 0x2800 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_rdbah() -> TestResult {
    if reg::RDBAH != 0x2804 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_rdlen() -> TestResult {
    if reg::RDLEN != 0x2808 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_rdh() -> TestResult {
    if reg::RDH != 0x2810 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_rdt() -> TestResult {
    if reg::RDT != 0x2818 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_tdbal() -> TestResult {
    if reg::TDBAL != 0x3800 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_tdbah() -> TestResult {
    if reg::TDBAH != 0x3804 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_tdlen() -> TestResult {
    if reg::TDLEN != 0x3808 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_tdh() -> TestResult {
    if reg::TDH != 0x3810 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_tdt() -> TestResult {
    if reg::TDT != 0x3818 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_ral0() -> TestResult {
    if reg::RAL0 != 0x5400 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_rah0() -> TestResult {
    if reg::RAH0 != 0x5404 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_mta() -> TestResult {
    if reg::MTA != 0x5200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ctrl_fd() -> TestResult {
    if ctrl::FD != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ctrl_lrst() -> TestResult {
    if ctrl::LRST != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ctrl_asde() -> TestResult {
    if ctrl::ASDE != 1 << 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ctrl_slu() -> TestResult {
    if ctrl::SLU != 1 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ctrl_ilos() -> TestResult {
    if ctrl::ILOS != 1 << 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ctrl_rst() -> TestResult {
    if ctrl::RST != 1 << 26 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ctrl_vme() -> TestResult {
    if ctrl::VME != 1 << 30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ctrl_phy_rst() -> TestResult {
    if ctrl::PHY_RST != 1u32 << 31 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_status_fd() -> TestResult {
    if status::FD != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_status_lu() -> TestResult {
    if status::LU != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_status_txoff() -> TestResult {
    if status::TXOFF != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_status_speed_mask() -> TestResult {
    if status::SPEED_MASK != 3 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_status_speed_10() -> TestResult {
    if status::SPEED_10 != 0 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_status_speed_100() -> TestResult {
    if status::SPEED_100 != 1 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_status_speed_1000() -> TestResult {
    if status::SPEED_1000 != 2 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rctl_en() -> TestResult {
    if rctl::EN != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rctl_sbp() -> TestResult {
    if rctl::SBP != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rctl_upe() -> TestResult {
    if rctl::UPE != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rctl_mpe() -> TestResult {
    if rctl::MPE != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rctl_lpe() -> TestResult {
    if rctl::LPE != 1 << 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rctl_lbm_none() -> TestResult {
    if rctl::LBM_NONE != 0 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rctl_rdmts_half() -> TestResult {
    if rctl::RDMTS_HALF != 0 << 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rctl_bam() -> TestResult {
    if rctl::BAM != 1 << 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rctl_bsize_2048() -> TestResult {
    if rctl::BSIZE_2048 != 0 << 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rctl_bsize_1024() -> TestResult {
    if rctl::BSIZE_1024 != 1 << 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rctl_bsize_512() -> TestResult {
    if rctl::BSIZE_512 != 2 << 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rctl_bsize_256() -> TestResult {
    if rctl::BSIZE_256 != 3 << 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rctl_secrc() -> TestResult {
    if rctl::SECRC != 1 << 26 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tctl_en() -> TestResult {
    if tctl::EN != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tctl_psp() -> TestResult {
    if tctl::PSP != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tctl_ct_shift() -> TestResult {
    if tctl::CT_SHIFT != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tctl_cold_shift() -> TestResult {
    if tctl::COLD_SHIFT != 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tctl_swxoff() -> TestResult {
    if tctl::SWXOFF != 1 << 22 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tctl_rtlc() -> TestResult {
    if tctl::RTLC != 1 << 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_txdw() -> TestResult {
    if int::TXDW != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_txqe() -> TestResult {
    if int::TXQE != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_lsc() -> TestResult {
    if int::LSC != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_rxseq() -> TestResult {
    if int::RXSEQ != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_rxdmt0() -> TestResult {
    if int::RXDMT0 != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_rxo() -> TestResult {
    if int::RXO != 1 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_int_rxt0() -> TestResult {
    if int::RXT0 != 1 << 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_cmd_eop() -> TestResult {
    if tx_cmd::EOP != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_cmd_ifcs() -> TestResult {
    if tx_cmd::IFCS != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_cmd_ic() -> TestResult {
    if tx_cmd::IC != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_cmd_rs() -> TestResult {
    if tx_cmd::RS != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_cmd_rps() -> TestResult {
    if tx_cmd::RPS != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_cmd_dext() -> TestResult {
    if tx_cmd::DEXT != 1 << 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_cmd_vle() -> TestResult {
    if tx_cmd::VLE != 1 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_cmd_ide() -> TestResult {
    if tx_cmd::IDE != 1 << 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_count() -> TestResult {
    if RX_DESC_COUNT != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_count() -> TestResult {
    if TX_DESC_COUNT != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_size() -> TestResult {
    if BUFFER_SIZE != 2048 {
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

pub(crate) fn test_desc_alignment() -> TestResult {
    if DESC_ALIGNMENT != 128 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_tipg() -> TestResult {
    if DEFAULT_TIPG != 0x0060200A {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_collision_threshold() -> TestResult {
    if DEFAULT_COLLISION_THRESHOLD != 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_collision_distance() -> TestResult {
    if DEFAULT_COLLISION_DISTANCE != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_size_larger_than_mtu() -> TestResult {
    if !(BUFFER_SIZE > MAX_MTU) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_desc_count_power_of_two() -> TestResult {
    if !RX_DESC_COUNT.is_power_of_two() {
        return TestResult::Fail;
    }
    if !TX_DESC_COUNT.is_power_of_two() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_tx_ring_spacing() -> TestResult {
    if reg::RDBAH - reg::RDBAL != 4 {
        return TestResult::Fail;
    }
    if reg::TDBAH - reg::TDBAL != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
