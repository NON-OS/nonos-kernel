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
pub mod header;
pub mod validation;

use crate::test::framework::TestSuite;

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("virtio_net");

    // constants tests
    suite.add_test("test_min_ethernet_frame", constants::test_min_ethernet_frame);
    suite.add_test("test_max_mtu", constants::test_max_mtu);
    suite.add_test("test_max_ethernet_frame", constants::test_max_ethernet_frame);
    suite.add_test("test_ethernet_header_size", constants::test_ethernet_header_size);
    suite.add_test("test_frame_size_ordering", constants::test_frame_size_ordering);
    suite.add_test("test_max_desc_chain_len", constants::test_max_desc_chain_len);
    suite.add_test("test_rate_limit_rx_pps", constants::test_rate_limit_rx_pps);
    suite.add_test("test_rate_limit_tx_pps", constants::test_rate_limit_tx_pps);
    suite.add_test("test_rate_limit_burst_rx", constants::test_rate_limit_burst_rx);
    suite.add_test("test_rate_limit_burst_tx", constants::test_rate_limit_burst_tx);
    suite.add_test("test_rate_limit_window_ms", constants::test_rate_limit_window_ms);
    suite.add_test("test_dma_alignment", constants::test_dma_alignment);
    suite.add_test("test_max_dma_region_size", constants::test_max_dma_region_size);
    suite.add_test("test_virtio_vendor_id", constants::test_virtio_vendor_id);
    suite.add_test(
        "test_virtio_net_device_id_transitional",
        constants::test_virtio_net_device_id_transitional,
    );
    suite.add_test("test_virtio_net_device_id_modern", constants::test_virtio_net_device_id_modern);
    suite.add_test("test_virtio_net_feature_mac", constants::test_virtio_net_feature_mac);
    suite.add_test("test_virtio_net_feature_status", constants::test_virtio_net_feature_status);
    suite.add_test("test_virtio_net_feature_ctrl_vq", constants::test_virtio_net_feature_ctrl_vq);
    suite.add_test("test_virtio_net_feature_csum", constants::test_virtio_net_feature_csum);
    suite.add_test("test_queue_rx", constants::test_queue_rx);
    suite.add_test("test_queue_tx", constants::test_queue_tx);
    suite.add_test("test_queue_ctrl", constants::test_queue_ctrl);
    suite.add_test("test_default_queue_size", constants::test_default_queue_size);
    suite.add_test("test_ctrl_queue_size", constants::test_ctrl_queue_size);
    suite.add_test("test_virtio_net_hdr_f_needs_csum", constants::test_virtio_net_hdr_f_needs_csum);
    suite.add_test("test_virtio_net_hdr_f_data_valid", constants::test_virtio_net_hdr_f_data_valid);
    suite.add_test("test_virtio_net_hdr_f_rsc_info", constants::test_virtio_net_hdr_f_rsc_info);
    suite.add_test("test_virtio_net_hdr_f_all_valid", constants::test_virtio_net_hdr_f_all_valid);
    suite.add_test("test_virtio_net_hdr_gso_none", constants::test_virtio_net_hdr_gso_none);
    suite.add_test("test_virtio_net_hdr_gso_tcpv4", constants::test_virtio_net_hdr_gso_tcpv4);
    suite.add_test("test_virtio_net_hdr_gso_udp", constants::test_virtio_net_hdr_gso_udp);
    suite.add_test("test_virtio_net_hdr_gso_tcpv6", constants::test_virtio_net_hdr_gso_tcpv6);
    suite.add_test("test_virtio_net_hdr_gso_ecn", constants::test_virtio_net_hdr_gso_ecn);
    suite.add_test("test_virtio_pci_cap_vendor", constants::test_virtio_pci_cap_vendor);
    suite.add_test("test_cap_common_cfg", constants::test_cap_common_cfg);
    suite.add_test("test_cap_notify_cfg", constants::test_cap_notify_cfg);
    suite.add_test("test_cap_isr_cfg", constants::test_cap_isr_cfg);
    suite.add_test("test_cap_device_cfg", constants::test_cap_device_cfg);
    suite.add_test("test_cap_pci_cfg", constants::test_cap_pci_cfg);
    suite.add_test("test_virtio_status_acknowledge", constants::test_virtio_status_acknowledge);
    suite.add_test("test_virtio_status_driver", constants::test_virtio_status_driver);
    suite.add_test("test_virtio_status_driver_ok", constants::test_virtio_status_driver_ok);
    suite.add_test("test_virtio_status_features_ok", constants::test_virtio_status_features_ok);
    suite.add_test(
        "test_virtio_status_device_needs_reset",
        constants::test_virtio_status_device_needs_reset,
    );
    suite.add_test("test_virtio_status_failed", constants::test_virtio_status_failed);
    suite.add_test("test_virtq_desc_f_next", constants::test_virtq_desc_f_next);
    suite.add_test("test_virtq_desc_f_write", constants::test_virtq_desc_f_write);
    suite.add_test("test_virtq_desc_f_indirect", constants::test_virtq_desc_f_indirect);
    suite.add_test("test_rx_buffer_size", constants::test_rx_buffer_size);
    suite.add_test("test_tx_buffer_size", constants::test_tx_buffer_size);
    suite.add_test("test_default_rx_buffer_count", constants::test_default_rx_buffer_count);
    suite.add_test("test_default_tx_buffer_count", constants::test_default_tx_buffer_count);
    suite.add_test("test_initial_rx_prime_count", constants::test_initial_rx_prime_count);
    suite.add_test("test_device_reset_timeout", constants::test_device_reset_timeout);
    suite.add_test("test_queue_timeout", constants::test_queue_timeout);
    suite.add_test(
        "test_rate_limit_burst_within_limits",
        constants::test_rate_limit_burst_within_limits,
    );
    suite.add_test("test_virtq_desc_flags_unique", constants::test_virtq_desc_flags_unique);

    // error tests
    suite.add_test("test_error_invalid_packet_size", error::test_error_invalid_packet_size);
    suite.add_test("test_error_packet_too_small", error::test_error_packet_too_small);
    suite.add_test("test_error_packet_exceeds_mtu", error::test_error_packet_exceeds_mtu);
    suite.add_test("test_error_invalid_header", error::test_error_invalid_header);
    suite.add_test(
        "test_error_descriptor_out_of_bounds",
        error::test_error_descriptor_out_of_bounds,
    );
    suite.add_test(
        "test_error_descriptor_chain_too_long",
        error::test_error_descriptor_chain_too_long,
    );
    suite.add_test("test_error_invalid_dma_address", error::test_error_invalid_dma_address);
    suite.add_test("test_error_rate_limit_exceeded", error::test_error_rate_limit_exceeded);
    suite.add_test("test_error_no_buffers_available", error::test_error_no_buffers_available);
    suite.add_test(
        "test_error_no_descriptors_available",
        error::test_error_no_descriptors_available,
    );
    suite.add_test("test_error_queue_error", error::test_error_queue_error);
    suite.add_test("test_error_invalid_mac_address", error::test_error_invalid_mac_address);
    suite.add_test("test_error_malformed_packet", error::test_error_malformed_packet);
    suite.add_test("test_error_checksum_error", error::test_error_checksum_error);
    suite.add_test("test_error_device_not_ready", error::test_error_device_not_ready);
    suite.add_test("test_error_buffer_too_small", error::test_error_buffer_too_small);
    suite.add_test("test_error_initialization_failed", error::test_error_initialization_failed);
    suite.add_test(
        "test_error_feature_negotiation_failed",
        error::test_error_feature_negotiation_failed,
    );
    suite.add_test(
        "test_error_msix_configuration_failed",
        error::test_error_msix_configuration_failed,
    );
    suite.add_test("test_error_queue_setup_failed", error::test_error_queue_setup_failed);
    suite.add_test("test_error_allocation_failed", error::test_error_allocation_failed);
    suite.add_test("test_error_generic_error", error::test_error_generic_error);
    suite.add_test(
        "test_is_security_relevant_rate_limit",
        error::test_is_security_relevant_rate_limit,
    );
    suite.add_test(
        "test_is_security_relevant_invalid_mac",
        error::test_is_security_relevant_invalid_mac,
    );
    suite.add_test(
        "test_is_security_relevant_malformed_packet",
        error::test_is_security_relevant_malformed_packet,
    );
    suite.add_test(
        "test_is_security_relevant_invalid_header",
        error::test_is_security_relevant_invalid_header,
    );
    suite.add_test(
        "test_is_security_relevant_descriptor_out_of_bounds",
        error::test_is_security_relevant_descriptor_out_of_bounds,
    );
    suite.add_test(
        "test_is_not_security_relevant_buffer_too_small",
        error::test_is_not_security_relevant_buffer_too_small,
    );
    suite.add_test(
        "test_is_recoverable_packet_too_small",
        error::test_is_recoverable_packet_too_small,
    );
    suite.add_test("test_is_recoverable_no_buffers", error::test_is_recoverable_no_buffers);
    suite.add_test(
        "test_is_not_recoverable_queue_error",
        error::test_is_not_recoverable_queue_error,
    );
    suite.add_test(
        "test_is_fatal_descriptor_out_of_bounds",
        error::test_is_fatal_descriptor_out_of_bounds,
    );
    suite.add_test("test_is_fatal_queue_error", error::test_is_fatal_queue_error);
    suite.add_test("test_is_not_fatal_packet_too_small", error::test_is_not_fatal_packet_too_small);
    suite.add_test("test_category_packet_size", error::test_category_packet_size);
    suite.add_test("test_category_packet_format", error::test_category_packet_format);
    suite.add_test("test_category_descriptor", error::test_category_descriptor);
    suite.add_test("test_category_memory", error::test_category_memory);
    suite.add_test("test_category_security", error::test_category_security);
    suite.add_test("test_category_device", error::test_category_device);
    suite.add_test("test_error_category_as_str", error::test_error_category_as_str);
    suite.add_test("test_error_equality", error::test_error_equality);
    suite.add_test("test_error_display", error::test_error_display);
    suite.add_test("test_all_errors_have_message", error::test_all_errors_have_message);

    // header tests
    suite.add_test("test_header_size_const", header::test_header_size_const);
    suite.add_test("test_header_size_of", header::test_header_size_of);
    suite.add_test("test_default_header", header::test_default_header);
    suite.add_test("test_new_header", header::test_new_header);
    suite.add_test("test_simple_header", header::test_simple_header);
    suite.add_test("test_default_validates", header::test_default_validates);
    suite.add_test("test_default_no_gso", header::test_default_no_gso);
    suite.add_test("test_default_no_csum", header::test_default_no_csum);
    suite.add_test("test_with_csum", header::test_with_csum);
    suite.add_test("test_invalid_flags", header::test_invalid_flags);
    suite.add_test("test_invalid_gso_type", header::test_invalid_gso_type);
    suite.add_test(
        "test_gso_tcpv4_invalid_without_params",
        header::test_gso_tcpv4_invalid_without_params,
    );
    suite.add_test("test_gso_tcpv4_valid_with_params", header::test_gso_tcpv4_valid_with_params);
    suite.add_test("test_gso_tcpv6", header::test_gso_tcpv6);
    suite.add_test("test_gso_udp", header::test_gso_udp);
    suite.add_test("test_invalid_num_buffers_zero", header::test_invalid_num_buffers_zero);
    suite
        .add_test("test_invalid_num_buffers_too_large", header::test_invalid_num_buffers_too_large);
    suite.add_test("test_valid_num_buffers", header::test_valid_num_buffers);
    suite.add_test("test_has_gso_none", header::test_has_gso_none);
    suite.add_test("test_has_gso_tcpv4", header::test_has_gso_tcpv4);
    suite.add_test("test_has_ecn", header::test_has_ecn);
    suite.add_test("test_csum_valid_flag", header::test_csum_valid_flag);
    suite.add_test("test_gso_type_name_none", header::test_gso_type_name_none);
    suite.add_test("test_gso_type_name_tcpv4", header::test_gso_type_name_tcpv4);
    suite.add_test("test_gso_type_name_tcpv6", header::test_gso_type_name_tcpv6);
    suite.add_test("test_gso_type_name_udp", header::test_gso_type_name_udp);
    suite.add_test("test_gso_type_name_with_ecn", header::test_gso_type_name_with_ecn);
    suite.add_test("test_as_bytes_length", header::test_as_bytes_length);
    suite.add_test("test_invalid_csum_start_too_large", header::test_invalid_csum_start_too_large);
    suite
        .add_test("test_invalid_csum_offset_too_large", header::test_invalid_csum_offset_too_large);
    suite.add_test("test_header_copy", header::test_header_copy);
    suite.add_test("test_header_clone", header::test_header_clone);

    // validation tests
    suite.add_test("test_packet_size_valid_min", validation::test_packet_size_valid_min);
    suite.add_test("test_packet_size_valid_max", validation::test_packet_size_valid_max);
    suite.add_test("test_packet_size_valid_typical", validation::test_packet_size_valid_typical);
    suite.add_test("test_packet_size_too_small", validation::test_packet_size_too_small);
    suite.add_test("test_packet_size_too_large", validation::test_packet_size_too_large);
    suite
        .add_test("test_descriptor_index_valid_zero", validation::test_descriptor_index_valid_zero);
    suite.add_test("test_descriptor_index_valid_max", validation::test_descriptor_index_valid_max);
    suite.add_test("test_descriptor_index_invalid", validation::test_descriptor_index_invalid);
    suite.add_test("test_descriptor_index_overflow", validation::test_descriptor_index_overflow);
    suite.add_test("test_chain_length_valid", validation::test_chain_length_valid);
    suite.add_test("test_chain_length_empty", validation::test_chain_length_empty);
    suite.add_test("test_chain_length_too_long", validation::test_chain_length_too_long);
    suite.add_test("test_chain_length_max_valid", validation::test_chain_length_max_valid);
    suite.add_test("test_mac_valid", validation::test_mac_valid);
    suite.add_test("test_mac_all_zeros", validation::test_mac_all_zeros);
    suite.add_test("test_mac_all_ones", validation::test_mac_all_ones);
    suite.add_test("test_source_mac_valid", validation::test_source_mac_valid);
    suite.add_test("test_source_mac_multicast", validation::test_source_mac_multicast);
    suite.add_test("test_ethernet_frame_valid", validation::test_ethernet_frame_valid);
    suite.add_test("test_ethernet_frame_too_short", validation::test_ethernet_frame_too_short);
    suite.add_test("test_ethertype_ipv4", validation::test_ethertype_ipv4);
    suite.add_test("test_ethertype_arp", validation::test_ethertype_arp);
    suite.add_test("test_ethertype_ipv6", validation::test_ethertype_ipv6);
    suite.add_test("test_ethertype_other", validation::test_ethertype_other);
    suite.add_test("test_ethertype_equality", validation::test_ethertype_equality);
    suite.add_test("test_ethertype_other_values", validation::test_ethertype_other_values);

    suite.run()
}
