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

pub mod constants;
pub mod descriptors;
pub mod error;

use crate::test::framework::TestSuite;

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("e1000");

    // constants tests (66 tests)
    suite.add_test("test_intel_vendor_id", constants::test_intel_vendor_id);
    suite.add_test("test_device_ids_not_empty", constants::test_device_ids_not_empty);
    suite.add_test("test_device_id_classic_100e", constants::test_device_id_classic_100e);
    suite.add_test("test_device_id_classic_100f", constants::test_device_id_classic_100f);
    suite.add_test("test_device_id_i210", constants::test_device_id_i210);
    suite.add_test("test_device_id_i219", constants::test_device_id_i219);
    suite.add_test("test_device_id_i350", constants::test_device_id_i350);
    suite.add_test("test_reg_ctrl", constants::test_reg_ctrl);
    suite.add_test("test_reg_status", constants::test_reg_status);
    suite.add_test("test_reg_eecd", constants::test_reg_eecd);
    suite.add_test("test_reg_eerd", constants::test_reg_eerd);
    suite.add_test("test_reg_icr", constants::test_reg_icr);
    suite.add_test("test_reg_itr", constants::test_reg_itr);
    suite.add_test("test_reg_ics", constants::test_reg_ics);
    suite.add_test("test_reg_ims", constants::test_reg_ims);
    suite.add_test("test_reg_imc", constants::test_reg_imc);
    suite.add_test("test_reg_rctl", constants::test_reg_rctl);
    suite.add_test("test_reg_tctl", constants::test_reg_tctl);
    suite.add_test("test_reg_tipg", constants::test_reg_tipg);
    suite.add_test("test_reg_rdbal", constants::test_reg_rdbal);
    suite.add_test("test_reg_rdbah", constants::test_reg_rdbah);
    suite.add_test("test_reg_rdlen", constants::test_reg_rdlen);
    suite.add_test("test_reg_rdh", constants::test_reg_rdh);
    suite.add_test("test_reg_rdt", constants::test_reg_rdt);
    suite.add_test("test_reg_tdbal", constants::test_reg_tdbal);
    suite.add_test("test_reg_tdbah", constants::test_reg_tdbah);
    suite.add_test("test_reg_tdlen", constants::test_reg_tdlen);
    suite.add_test("test_reg_tdh", constants::test_reg_tdh);
    suite.add_test("test_reg_tdt", constants::test_reg_tdt);
    suite.add_test("test_reg_ral0", constants::test_reg_ral0);
    suite.add_test("test_reg_rah0", constants::test_reg_rah0);
    suite.add_test("test_reg_mta", constants::test_reg_mta);
    suite.add_test("test_ctrl_fd", constants::test_ctrl_fd);
    suite.add_test("test_ctrl_lrst", constants::test_ctrl_lrst);
    suite.add_test("test_ctrl_asde", constants::test_ctrl_asde);
    suite.add_test("test_ctrl_slu", constants::test_ctrl_slu);
    suite.add_test("test_ctrl_ilos", constants::test_ctrl_ilos);
    suite.add_test("test_ctrl_rst", constants::test_ctrl_rst);
    suite.add_test("test_ctrl_vme", constants::test_ctrl_vme);
    suite.add_test("test_ctrl_phy_rst", constants::test_ctrl_phy_rst);
    suite.add_test("test_status_fd", constants::test_status_fd);
    suite.add_test("test_status_lu", constants::test_status_lu);
    suite.add_test("test_status_txoff", constants::test_status_txoff);
    suite.add_test("test_status_speed_mask", constants::test_status_speed_mask);
    suite.add_test("test_status_speed_10", constants::test_status_speed_10);
    suite.add_test("test_status_speed_100", constants::test_status_speed_100);
    suite.add_test("test_status_speed_1000", constants::test_status_speed_1000);
    suite.add_test("test_rctl_en", constants::test_rctl_en);
    suite.add_test("test_rctl_sbp", constants::test_rctl_sbp);
    suite.add_test("test_rctl_upe", constants::test_rctl_upe);
    suite.add_test("test_rctl_mpe", constants::test_rctl_mpe);
    suite.add_test("test_rctl_lpe", constants::test_rctl_lpe);
    suite.add_test("test_rctl_lbm_none", constants::test_rctl_lbm_none);
    suite.add_test("test_rctl_rdmts_half", constants::test_rctl_rdmts_half);
    suite.add_test("test_rctl_bam", constants::test_rctl_bam);
    suite.add_test("test_rctl_bsize_2048", constants::test_rctl_bsize_2048);
    suite.add_test("test_rctl_bsize_1024", constants::test_rctl_bsize_1024);
    suite.add_test("test_rctl_bsize_512", constants::test_rctl_bsize_512);
    suite.add_test("test_rctl_bsize_256", constants::test_rctl_bsize_256);
    suite.add_test("test_rctl_secrc", constants::test_rctl_secrc);
    suite.add_test("test_tctl_en", constants::test_tctl_en);
    suite.add_test("test_tctl_psp", constants::test_tctl_psp);
    suite.add_test("test_tctl_ct_shift", constants::test_tctl_ct_shift);
    suite.add_test("test_tctl_cold_shift", constants::test_tctl_cold_shift);
    suite.add_test("test_tctl_swxoff", constants::test_tctl_swxoff);
    suite.add_test("test_tctl_rtlc", constants::test_tctl_rtlc);
    suite.add_test("test_int_txdw", constants::test_int_txdw);
    suite.add_test("test_int_txqe", constants::test_int_txqe);
    suite.add_test("test_int_lsc", constants::test_int_lsc);
    suite.add_test("test_int_rxseq", constants::test_int_rxseq);
    suite.add_test("test_int_rxdmt0", constants::test_int_rxdmt0);
    suite.add_test("test_int_rxo", constants::test_int_rxo);
    suite.add_test("test_int_rxt0", constants::test_int_rxt0);
    suite.add_test("test_tx_cmd_eop", constants::test_tx_cmd_eop);
    suite.add_test("test_tx_cmd_ifcs", constants::test_tx_cmd_ifcs);
    suite.add_test("test_tx_cmd_ic", constants::test_tx_cmd_ic);
    suite.add_test("test_tx_cmd_rs", constants::test_tx_cmd_rs);
    suite.add_test("test_tx_cmd_rps", constants::test_tx_cmd_rps);
    suite.add_test("test_tx_cmd_dext", constants::test_tx_cmd_dext);
    suite.add_test("test_tx_cmd_vle", constants::test_tx_cmd_vle);
    suite.add_test("test_tx_cmd_ide", constants::test_tx_cmd_ide);
    suite.add_test("test_rx_desc_count", constants::test_rx_desc_count);
    suite.add_test("test_tx_desc_count", constants::test_tx_desc_count);
    suite.add_test("test_buffer_size", constants::test_buffer_size);
    suite.add_test("test_min_frame_size", constants::test_min_frame_size);
    suite.add_test("test_max_mtu", constants::test_max_mtu);
    suite.add_test("test_desc_alignment", constants::test_desc_alignment);
    suite.add_test("test_default_tipg", constants::test_default_tipg);
    suite.add_test("test_default_collision_threshold", constants::test_default_collision_threshold);
    suite.add_test("test_default_collision_distance", constants::test_default_collision_distance);
    suite.add_test("test_buffer_size_larger_than_mtu", constants::test_buffer_size_larger_than_mtu);
    suite.add_test("test_desc_count_power_of_two", constants::test_desc_count_power_of_two);
    suite.add_test("test_rx_tx_ring_spacing", constants::test_rx_tx_ring_spacing);

    // descriptors tests (38 tests)
    suite.add_test("test_rx_desc_size", descriptors::test_rx_desc_size);
    suite.add_test("test_tx_desc_size", descriptors::test_tx_desc_size);
    suite.add_test("test_rx_desc_default", descriptors::test_rx_desc_default);
    suite.add_test("test_tx_desc_default", descriptors::test_tx_desc_default);
    suite.add_test("test_rx_desc_status_dd", descriptors::test_rx_desc_status_dd);
    suite.add_test("test_rx_desc_status_eop", descriptors::test_rx_desc_status_eop);
    suite.add_test("test_rx_desc_status_ixsm", descriptors::test_rx_desc_status_ixsm);
    suite.add_test("test_rx_desc_status_vp", descriptors::test_rx_desc_status_vp);
    suite.add_test("test_rx_desc_status_tcpcs", descriptors::test_rx_desc_status_tcpcs);
    suite.add_test("test_rx_desc_status_ipcs", descriptors::test_rx_desc_status_ipcs);
    suite.add_test("test_rx_desc_is_done_false", descriptors::test_rx_desc_is_done_false);
    suite.add_test("test_rx_desc_is_done_true", descriptors::test_rx_desc_is_done_true);
    suite.add_test("test_rx_desc_is_eop_false", descriptors::test_rx_desc_is_eop_false);
    suite.add_test("test_rx_desc_is_eop_true", descriptors::test_rx_desc_is_eop_true);
    suite.add_test("test_rx_desc_has_error_false", descriptors::test_rx_desc_has_error_false);
    suite.add_test("test_rx_desc_has_error_true", descriptors::test_rx_desc_has_error_true);
    suite.add_test("test_rx_desc_is_vlan_false", descriptors::test_rx_desc_is_vlan_false);
    suite.add_test("test_rx_desc_is_vlan_true", descriptors::test_rx_desc_is_vlan_true);
    suite.add_test("test_rx_desc_vlan_tag_none", descriptors::test_rx_desc_vlan_tag_none);
    suite.add_test("test_rx_desc_vlan_tag_some", descriptors::test_rx_desc_vlan_tag_some);
    suite.add_test("test_rx_desc_packet_len", descriptors::test_rx_desc_packet_len);
    suite.add_test("test_rx_desc_reset", descriptors::test_rx_desc_reset);
    suite.add_test("test_tx_desc_status_dd", descriptors::test_tx_desc_status_dd);
    suite.add_test("test_tx_desc_status_ec", descriptors::test_tx_desc_status_ec);
    suite.add_test("test_tx_desc_status_lc", descriptors::test_tx_desc_status_lc);
    suite.add_test("test_tx_desc_is_done_false", descriptors::test_tx_desc_is_done_false);
    suite.add_test("test_tx_desc_is_done_true", descriptors::test_tx_desc_is_done_true);
    suite.add_test(
        "test_tx_desc_had_excess_collisions_false",
        descriptors::test_tx_desc_had_excess_collisions_false,
    );
    suite.add_test(
        "test_tx_desc_had_excess_collisions_true",
        descriptors::test_tx_desc_had_excess_collisions_true,
    );
    suite.add_test(
        "test_tx_desc_had_late_collision_false",
        descriptors::test_tx_desc_had_late_collision_false,
    );
    suite.add_test(
        "test_tx_desc_had_late_collision_true",
        descriptors::test_tx_desc_had_late_collision_true,
    );
    suite.add_test("test_tx_desc_has_error_false", descriptors::test_tx_desc_has_error_false);
    suite.add_test("test_tx_desc_has_error_true_ec", descriptors::test_tx_desc_has_error_true_ec);
    suite.add_test("test_tx_desc_has_error_true_lc", descriptors::test_tx_desc_has_error_true_lc);
    suite.add_test("test_tx_desc_setup", descriptors::test_tx_desc_setup);
    suite.add_test("test_tx_desc_reset", descriptors::test_tx_desc_reset);
    suite.add_test("test_rx_desc_copy", descriptors::test_rx_desc_copy);
    suite.add_test("test_tx_desc_copy", descriptors::test_tx_desc_copy);
    suite.add_test("test_rx_desc_done_and_eop", descriptors::test_rx_desc_done_and_eop);
    suite.add_test("test_tx_desc_done_but_error", descriptors::test_tx_desc_done_but_error);

    // error tests (40 tests)
    suite.add_test("test_error_device_not_found_str", error::test_error_device_not_found_str);
    suite.add_test(
        "test_error_initialization_failed_str",
        error::test_error_initialization_failed_str,
    );
    suite.add_test("test_error_invalid_bar_str", error::test_error_invalid_bar_str);
    suite.add_test("test_error_eeprom_timeout_str", error::test_error_eeprom_timeout_str);
    suite.add_test("test_error_eeprom_read_failed_str", error::test_error_eeprom_read_failed_str);
    suite.add_test("test_error_link_down_str", error::test_error_link_down_str);
    suite.add_test("test_error_tx_queue_full_str", error::test_error_tx_queue_full_str);
    suite.add_test("test_error_tx_timeout_str", error::test_error_tx_timeout_str);
    suite.add_test("test_error_rx_buffer_empty_str", error::test_error_rx_buffer_empty_str);
    suite.add_test("test_error_invalid_packet_size_str", error::test_error_invalid_packet_size_str);
    suite.add_test(
        "test_error_dma_allocation_failed_str",
        error::test_error_dma_allocation_failed_str,
    );
    suite.add_test("test_error_invalid_mtu_str", error::test_error_invalid_mtu_str);
    suite.add_test("test_error_phy_error_str", error::test_error_phy_error_str);
    suite.add_test("test_error_reset_failed_str", error::test_error_reset_failed_str);
    suite.add_test("test_error_interrupt_error_str", error::test_error_interrupt_error_str);
    suite.add_test(
        "test_error_tx_queue_full_recoverable",
        error::test_error_tx_queue_full_recoverable,
    );
    suite.add_test(
        "test_error_rx_buffer_empty_recoverable",
        error::test_error_rx_buffer_empty_recoverable,
    );
    suite.add_test("test_error_link_down_recoverable", error::test_error_link_down_recoverable);
    suite.add_test("test_error_tx_timeout_recoverable", error::test_error_tx_timeout_recoverable);
    suite.add_test(
        "test_error_device_not_found_not_recoverable",
        error::test_error_device_not_found_not_recoverable,
    );
    suite.add_test(
        "test_error_initialization_failed_not_recoverable",
        error::test_error_initialization_failed_not_recoverable,
    );
    suite.add_test(
        "test_error_invalid_bar_not_recoverable",
        error::test_error_invalid_bar_not_recoverable,
    );
    suite.add_test(
        "test_error_eeprom_timeout_not_recoverable",
        error::test_error_eeprom_timeout_not_recoverable,
    );
    suite.add_test(
        "test_error_eeprom_read_failed_not_recoverable",
        error::test_error_eeprom_read_failed_not_recoverable,
    );
    suite.add_test(
        "test_error_dma_allocation_failed_not_recoverable",
        error::test_error_dma_allocation_failed_not_recoverable,
    );
    suite.add_test(
        "test_error_invalid_mtu_not_recoverable",
        error::test_error_invalid_mtu_not_recoverable,
    );
    suite.add_test(
        "test_error_phy_error_not_recoverable",
        error::test_error_phy_error_not_recoverable,
    );
    suite.add_test(
        "test_error_reset_failed_not_recoverable",
        error::test_error_reset_failed_not_recoverable,
    );
    suite.add_test(
        "test_error_interrupt_error_not_recoverable",
        error::test_error_interrupt_error_not_recoverable,
    );
    suite.add_test(
        "test_error_invalid_packet_size_not_recoverable",
        error::test_error_invalid_packet_size_not_recoverable,
    );
    suite.add_test("test_error_equality", error::test_error_equality);
    suite.add_test("test_error_copy", error::test_error_copy);
    suite.add_test("test_error_clone", error::test_error_clone);
    suite.add_test("test_error_debug", error::test_error_debug);
    suite.add_test("test_error_display", error::test_error_display);
    suite.add_test("test_all_errors_have_message", error::test_all_errors_have_message);

    suite.run()
}
