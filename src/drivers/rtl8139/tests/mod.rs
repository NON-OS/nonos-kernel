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
pub mod error;

use crate::test::framework::TestSuite;

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("rtl8139");

    // constants tests (81 tests)
    suite.add_test("test_realtek_vendor_id", constants::test_realtek_vendor_id);
    suite.add_test("test_device_ids_not_empty", constants::test_device_ids_not_empty);
    suite.add_test("test_device_id_rtl8139", constants::test_device_id_rtl8139);
    suite.add_test("test_device_id_rtl8138", constants::test_device_id_rtl8138);
    suite.add_test("test_device_id_rtl8129", constants::test_device_id_rtl8129);
    suite.add_test("test_device_id_rtl8131", constants::test_device_id_rtl8131);
    suite.add_test("test_device_id_rtl8136", constants::test_device_id_rtl8136);
    suite.add_test("test_device_id_rtl8100", constants::test_device_id_rtl8100);
    suite.add_test("test_reg_idr0", constants::test_reg_idr0);
    suite.add_test("test_reg_idr4", constants::test_reg_idr4);
    suite.add_test("test_reg_mar0", constants::test_reg_mar0);
    suite.add_test("test_reg_mar4", constants::test_reg_mar4);
    suite.add_test("test_reg_tsd0", constants::test_reg_tsd0);
    suite.add_test("test_reg_tsd1", constants::test_reg_tsd1);
    suite.add_test("test_reg_tsd2", constants::test_reg_tsd2);
    suite.add_test("test_reg_tsd3", constants::test_reg_tsd3);
    suite.add_test("test_reg_tsad0", constants::test_reg_tsad0);
    suite.add_test("test_reg_tsad1", constants::test_reg_tsad1);
    suite.add_test("test_reg_tsad2", constants::test_reg_tsad2);
    suite.add_test("test_reg_tsad3", constants::test_reg_tsad3);
    suite.add_test("test_reg_rbstart", constants::test_reg_rbstart);
    suite.add_test("test_reg_cr", constants::test_reg_cr);
    suite.add_test("test_reg_capr", constants::test_reg_capr);
    suite.add_test("test_reg_cbr", constants::test_reg_cbr);
    suite.add_test("test_reg_imr", constants::test_reg_imr);
    suite.add_test("test_reg_isr", constants::test_reg_isr);
    suite.add_test("test_reg_tcr", constants::test_reg_tcr);
    suite.add_test("test_reg_rcr", constants::test_reg_rcr);
    suite.add_test("test_reg_msr", constants::test_reg_msr);
    suite.add_test("test_reg_bmcr", constants::test_reg_bmcr);
    suite.add_test("test_reg_bmsr", constants::test_reg_bmsr);
    suite.add_test("test_cmd_bufe", constants::test_cmd_bufe);
    suite.add_test("test_cmd_te", constants::test_cmd_te);
    suite.add_test("test_cmd_re", constants::test_cmd_re);
    suite.add_test("test_cmd_rst", constants::test_cmd_rst);
    suite.add_test("test_rcr_aap", constants::test_rcr_aap);
    suite.add_test("test_rcr_apm", constants::test_rcr_apm);
    suite.add_test("test_rcr_am", constants::test_rcr_am);
    suite.add_test("test_rcr_ab", constants::test_rcr_ab);
    suite.add_test("test_rcr_ar", constants::test_rcr_ar);
    suite.add_test("test_rcr_aer", constants::test_rcr_aer);
    suite.add_test("test_rcr_wrap", constants::test_rcr_wrap);
    suite.add_test("test_rcr_rblen_8k", constants::test_rcr_rblen_8k);
    suite.add_test("test_rcr_rblen_16k", constants::test_rcr_rblen_16k);
    suite.add_test("test_rcr_rblen_32k", constants::test_rcr_rblen_32k);
    suite.add_test("test_rcr_rblen_64k", constants::test_rcr_rblen_64k);
    suite.add_test("test_tcr_clrabt", constants::test_tcr_clrabt);
    suite.add_test("test_tcr_mxdma_16", constants::test_tcr_mxdma_16);
    suite.add_test("test_tcr_mxdma_32", constants::test_tcr_mxdma_32);
    suite.add_test("test_tcr_mxdma_64", constants::test_tcr_mxdma_64);
    suite.add_test("test_tcr_mxdma_128", constants::test_tcr_mxdma_128);
    suite.add_test("test_tcr_mxdma_256", constants::test_tcr_mxdma_256);
    suite.add_test("test_tcr_mxdma_512", constants::test_tcr_mxdma_512);
    suite.add_test("test_tcr_mxdma_1024", constants::test_tcr_mxdma_1024);
    suite.add_test("test_tcr_mxdma_unlim", constants::test_tcr_mxdma_unlim);
    suite.add_test("test_tcr_ifg_std", constants::test_tcr_ifg_std);
    suite.add_test("test_tsd_own", constants::test_tsd_own);
    suite.add_test("test_tsd_tun", constants::test_tsd_tun);
    suite.add_test("test_tsd_tok", constants::test_tsd_tok);
    suite.add_test("test_int_rok", constants::test_int_rok);
    suite.add_test("test_int_rer", constants::test_int_rer);
    suite.add_test("test_int_tok", constants::test_int_tok);
    suite.add_test("test_int_ter", constants::test_int_ter);
    suite.add_test("test_int_rxovw", constants::test_int_rxovw);
    suite.add_test("test_int_pun", constants::test_int_pun);
    suite.add_test("test_int_fovw", constants::test_int_fovw);
    suite.add_test("test_int_timeout", constants::test_int_timeout);
    suite.add_test("test_int_serr", constants::test_int_serr);
    suite.add_test("test_msr_rxpf", constants::test_msr_rxpf);
    suite.add_test("test_msr_txpf", constants::test_msr_txpf);
    suite.add_test("test_msr_linkb", constants::test_msr_linkb);
    suite.add_test("test_msr_speed10", constants::test_msr_speed10);
    suite.add_test("test_msr_auxsts", constants::test_msr_auxsts);
    suite.add_test("test_msr_rxfce", constants::test_msr_rxfce);
    suite.add_test("test_msr_txfce", constants::test_msr_txfce);
    suite.add_test("test_rx_buffer_size", constants::test_rx_buffer_size);
    suite.add_test("test_tx_desc_count", constants::test_tx_desc_count);
    suite.add_test("test_tx_buffer_size", constants::test_tx_buffer_size);
    suite.add_test("test_min_frame_size", constants::test_min_frame_size);
    suite.add_test("test_max_mtu", constants::test_max_mtu);
    suite.add_test("test_tx_buffer_larger_than_mtu", constants::test_tx_buffer_larger_than_mtu);
    suite.add_test("test_rx_buffer_larger_than_8k", constants::test_rx_buffer_larger_than_8k);
    suite.add_test("test_tsd_registers_spacing", constants::test_tsd_registers_spacing);
    suite.add_test("test_tsad_registers_spacing", constants::test_tsad_registers_spacing);

    // error tests (38 tests)
    suite.add_test("test_error_device_not_found_str", error::test_error_device_not_found_str);
    suite.add_test(
        "test_error_initialization_failed_str",
        error::test_error_initialization_failed_str,
    );
    suite.add_test("test_error_invalid_bar_str", error::test_error_invalid_bar_str);
    suite.add_test("test_error_reset_timeout_str", error::test_error_reset_timeout_str);
    suite.add_test("test_error_tx_queue_full_str", error::test_error_tx_queue_full_str);
    suite.add_test("test_error_tx_timeout_str", error::test_error_tx_timeout_str);
    suite.add_test("test_error_rx_buffer_overflow_str", error::test_error_rx_buffer_overflow_str);
    suite.add_test("test_error_invalid_packet_size_str", error::test_error_invalid_packet_size_str);
    suite.add_test(
        "test_error_dma_allocation_failed_str",
        error::test_error_dma_allocation_failed_str,
    );
    suite.add_test("test_error_link_down_str", error::test_error_link_down_str);
    suite.add_test("test_error_crc_error_str", error::test_error_crc_error_str);
    suite.add_test(
        "test_error_frame_alignment_error_str",
        error::test_error_frame_alignment_error_str,
    );
    suite.add_test("test_error_runt_packet_str", error::test_error_runt_packet_str);
    suite.add_test("test_error_long_packet_str", error::test_error_long_packet_str);
    suite.add_test("test_error_fifo_error_str", error::test_error_fifo_error_str);
    suite.add_test(
        "test_error_tx_queue_full_recoverable",
        error::test_error_tx_queue_full_recoverable,
    );
    suite.add_test(
        "test_error_rx_buffer_overflow_recoverable",
        error::test_error_rx_buffer_overflow_recoverable,
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
        "test_error_reset_timeout_not_recoverable",
        error::test_error_reset_timeout_not_recoverable,
    );
    suite.add_test(
        "test_error_dma_allocation_failed_not_recoverable",
        error::test_error_dma_allocation_failed_not_recoverable,
    );
    suite.add_test(
        "test_error_crc_error_not_recoverable",
        error::test_error_crc_error_not_recoverable,
    );
    suite.add_test(
        "test_error_frame_alignment_error_not_recoverable",
        error::test_error_frame_alignment_error_not_recoverable,
    );
    suite.add_test(
        "test_error_runt_packet_not_recoverable",
        error::test_error_runt_packet_not_recoverable,
    );
    suite.add_test(
        "test_error_long_packet_not_recoverable",
        error::test_error_long_packet_not_recoverable,
    );
    suite.add_test(
        "test_error_fifo_error_not_recoverable",
        error::test_error_fifo_error_not_recoverable,
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
