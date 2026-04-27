// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Network subsystem test suite

mod boot_config_tests;
mod dns_tests;
mod ethernet_tests;
mod firewall_tests;
mod http_tests;
mod ip_tests;
mod nym_tests;
mod socks_tests;
mod stack_tests;
mod tcp_tests;
mod udp_tests;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("network");

    // IP tests (31 tests)
    suite.add(TestCase::new("ip_protocol_tcp", ip_tests::test_ip_protocol_tcp));
    suite.add(TestCase::new("ip_protocol_udp", ip_tests::test_ip_protocol_udp));
    suite.add(TestCase::new("ip_protocol_icmp", ip_tests::test_ip_protocol_icmp));
    suite.add(TestCase::new("ip_protocols_unique", ip_tests::test_ip_protocols_unique));
    suite.add(TestCase::new("ip_address_v4_create", ip_tests::test_ip_address_v4_create));
    suite.add(TestCase::new("ip_address_v4_variant", ip_tests::test_ip_address_v4_variant));
    suite.add(TestCase::new("ip_address_v6_variant", ip_tests::test_ip_address_v6_variant));
    suite.add(TestCase::new("ip_address_unspecified_v4", ip_tests::test_ip_address_unspecified_v4));
    suite.add(TestCase::new("ip_address_unspecified_v6", ip_tests::test_ip_address_unspecified_v6));
    suite.add(TestCase::new(
        "ip_address_not_unspecified_v4",
        ip_tests::test_ip_address_not_unspecified_v4,
    ));
    suite.add(TestCase::new(
        "ip_address_not_unspecified_v6",
        ip_tests::test_ip_address_not_unspecified_v6,
    ));
    suite.add(TestCase::new("ip_address_loopback_v4", ip_tests::test_ip_address_loopback_v4));
    suite.add(TestCase::new(
        "ip_address_loopback_v4_any",
        ip_tests::test_ip_address_loopback_v4_any,
    ));
    suite.add(TestCase::new("ip_address_loopback_v6", ip_tests::test_ip_address_loopback_v6));
    suite.add(TestCase::new(
        "ip_address_not_loopback_v4",
        ip_tests::test_ip_address_not_loopback_v4,
    ));
    suite.add(TestCase::new(
        "ip_address_not_loopback_v6",
        ip_tests::test_ip_address_not_loopback_v6,
    ));
    suite.add(TestCase::new("ip_address_equality_v4", ip_tests::test_ip_address_equality_v4));
    suite.add(TestCase::new("ip_address_equality_v6", ip_tests::test_ip_address_equality_v6));
    suite.add(TestCase::new(
        "ip_address_v4_v6_different",
        ip_tests::test_ip_address_v4_v6_different,
    ));
    suite.add(TestCase::new("ip_address_clone", ip_tests::test_ip_address_clone));
    suite.add(TestCase::new("ip_address_copy", ip_tests::test_ip_address_copy));
    suite.add(TestCase::new("ip_address_ordering_v4", ip_tests::test_ip_address_ordering_v4));
    suite.add(TestCase::new("ip_address_ordering_v6", ip_tests::test_ip_address_ordering_v6));
    suite.add(TestCase::new("ip_address_common_v4", ip_tests::test_ip_address_common_v4));
    suite.add(TestCase::new("ip_address_broadcast_v4", ip_tests::test_ip_address_broadcast_v4));
    suite.add(TestCase::new("ip_address_multicast_v4", ip_tests::test_ip_address_multicast_v4));
    suite.add(TestCase::new("ip_address_all_variants", ip_tests::test_ip_address_all_variants));
    suite.add(TestCase::new("ip_protocol_ordering", ip_tests::test_ip_protocol_ordering));
    suite.add(TestCase::new("ip_address_v4_bytes", ip_tests::test_ip_address_v4_bytes));
    suite.add(TestCase::new("ip_address_v6_bytes", ip_tests::test_ip_address_v6_bytes));

    // TCP tests (37 tests)
    suite.add(TestCase::new("tcp_syn_constant", tcp_tests::test_tcp_syn_constant));
    suite.add(TestCase::new("tcp_ack_constant", tcp_tests::test_tcp_ack_constant));
    suite.add(TestCase::new("tcp_fin_constant", tcp_tests::test_tcp_fin_constant));
    suite.add(TestCase::new("tcp_rst_constant", tcp_tests::test_tcp_rst_constant));
    suite.add(TestCase::new("tcp_psh_constant", tcp_tests::test_tcp_psh_constant));
    suite.add(TestCase::new("tcp_flags_unique", tcp_tests::test_tcp_flags_unique));
    suite.add(TestCase::new("tcp_flags_combinable", tcp_tests::test_tcp_flags_combinable));
    suite.add(TestCase::new("tcp_state_closed", tcp_tests::test_tcp_state_closed));
    suite.add(TestCase::new("tcp_state_listen", tcp_tests::test_tcp_state_listen));
    suite.add(TestCase::new("tcp_state_syn_sent", tcp_tests::test_tcp_state_syn_sent));
    suite.add(TestCase::new("tcp_state_syn_received", tcp_tests::test_tcp_state_syn_received));
    suite.add(TestCase::new("tcp_state_established", tcp_tests::test_tcp_state_established));
    suite.add(TestCase::new("tcp_state_fin_wait1", tcp_tests::test_tcp_state_fin_wait1));
    suite.add(TestCase::new("tcp_state_fin_wait2", tcp_tests::test_tcp_state_fin_wait2));
    suite.add(TestCase::new("tcp_state_close_wait", tcp_tests::test_tcp_state_close_wait));
    suite.add(TestCase::new("tcp_state_closing", tcp_tests::test_tcp_state_closing));
    suite.add(TestCase::new("tcp_state_last_ack", tcp_tests::test_tcp_state_last_ack));
    suite.add(TestCase::new("tcp_state_time_wait", tcp_tests::test_tcp_state_time_wait));
    suite.add(TestCase::new("tcp_state_equality", tcp_tests::test_tcp_state_equality));
    suite.add(TestCase::new("tcp_state_clone", tcp_tests::test_tcp_state_clone));
    suite.add(TestCase::new("tcp_state_copy", tcp_tests::test_tcp_state_copy));
    suite.add(TestCase::new("tcp_header_min_size", tcp_tests::test_tcp_header_min_size));
    suite.add(TestCase::new("tcp_header_is_syn", tcp_tests::test_tcp_header_is_syn));
    suite.add(TestCase::new("tcp_header_is_ack", tcp_tests::test_tcp_header_is_ack));
    suite.add(TestCase::new("tcp_header_is_fin", tcp_tests::test_tcp_header_is_fin));
    suite.add(TestCase::new("tcp_header_is_rst", tcp_tests::test_tcp_header_is_rst));
    suite.add(TestCase::new("tcp_header_syn_ack", tcp_tests::test_tcp_header_syn_ack));
    suite.add(TestCase::new("tcp_header_clone", tcp_tests::test_tcp_header_clone));
    suite.add(TestCase::new("tcp_header_max_ports", tcp_tests::test_tcp_header_max_ports));
    suite.add(TestCase::new("tcp_connection_new", tcp_tests::test_tcp_connection_new));
    suite.add(TestCase::new("tcp_connection_default", tcp_tests::test_tcp_connection_default));
    suite.add(TestCase::new("tcp_connection_fields", tcp_tests::test_tcp_connection_fields));
    suite.add(TestCase::new("tcp_connection_clone", tcp_tests::test_tcp_connection_clone));
    suite.add(TestCase::new("tcp_state_all_variants", tcp_tests::test_tcp_state_all_variants));
    suite.add(TestCase::new(
        "tcp_header_all_flags_combined",
        tcp_tests::test_tcp_header_all_flags_combined,
    ));
    suite.add(TestCase::new("tcp_connection_localhost", tcp_tests::test_tcp_connection_localhost));

    // UDP tests (27 tests)
    suite.add(TestCase::new("udp_state_unbound", udp_tests::test_udp_state_unbound));
    suite.add(TestCase::new("udp_state_bound", udp_tests::test_udp_state_bound));
    suite.add(TestCase::new("udp_state_connected", udp_tests::test_udp_state_connected));
    suite.add(TestCase::new("udp_state_closed", udp_tests::test_udp_state_closed));
    suite.add(TestCase::new("udp_state_equality", udp_tests::test_udp_state_equality));
    suite.add(TestCase::new("udp_state_clone", udp_tests::test_udp_state_clone));
    suite.add(TestCase::new("udp_stats_default", udp_tests::test_udp_stats_default));
    suite.add(TestCase::new("udp_stats_fields", udp_tests::test_udp_stats_fields));
    suite.add(TestCase::new("udp_stats_clone", udp_tests::test_udp_stats_clone));
    suite.add(TestCase::new("udp_header_parse_valid", udp_tests::test_udp_header_parse_valid));
    suite.add(TestCase::new(
        "udp_header_parse_too_short",
        udp_tests::test_udp_header_parse_too_short,
    ));
    suite.add(TestCase::new("udp_header_parse_empty", udp_tests::test_udp_header_parse_empty));
    suite.add(TestCase::new(
        "udp_header_parse_exact_size",
        udp_tests::test_udp_header_parse_exact_size,
    ));
    suite.add(TestCase::new("udp_header_serialize", udp_tests::test_udp_header_serialize));
    suite.add(TestCase::new(
        "udp_header_serialize_roundtrip",
        udp_tests::test_udp_header_serialize_roundtrip,
    ));
    suite.add(TestCase::new("udp_header_clone", udp_tests::test_udp_header_clone));
    suite.add(TestCase::new("udp_header_max_port", udp_tests::test_udp_header_max_port));
    suite.add(TestCase::new("udp_header_min_length", udp_tests::test_udp_header_min_length));
    suite.add(TestCase::new("udp_packet_fields", udp_tests::test_udp_packet_fields));
    suite.add(TestCase::new("udp_packet_clone", udp_tests::test_udp_packet_clone));
    suite.add(TestCase::new("udp_packet_empty_data", udp_tests::test_udp_packet_empty_data));
    suite.add(TestCase::new(
        "udp_header_calculate_checksum",
        udp_tests::test_udp_header_calculate_checksum,
    ));
    suite.add(TestCase::new(
        "udp_header_calculate_checksum_empty_data",
        udp_tests::test_udp_header_calculate_checksum_empty_data,
    ));
    suite.add(TestCase::new(
        "udp_header_calculate_checksum_odd_length",
        udp_tests::test_udp_header_calculate_checksum_odd_length,
    ));

    // DNS tests (52 tests)
    suite.add(TestCase::new(
        "dns_max_query_cache_constant",
        dns_tests::test_max_query_cache_constant,
    ));
    suite
        .add(TestCase::new("dns_default_ttl_ms_constant", dns_tests::test_default_ttl_ms_constant));
    suite.add(TestCase::new(
        "dns_max_cname_depth_constant",
        dns_tests::test_max_cname_depth_constant,
    ));
    suite.add(TestCase::new("dns_record_type_a", dns_tests::test_dns_record_type_a));
    suite.add(TestCase::new("dns_record_type_ns", dns_tests::test_dns_record_type_ns));
    suite.add(TestCase::new("dns_record_type_cname", dns_tests::test_dns_record_type_cname));
    suite.add(TestCase::new("dns_record_type_soa", dns_tests::test_dns_record_type_soa));
    suite.add(TestCase::new("dns_record_type_ptr", dns_tests::test_dns_record_type_ptr));
    suite.add(TestCase::new("dns_record_type_mx", dns_tests::test_dns_record_type_mx));
    suite.add(TestCase::new("dns_record_type_txt", dns_tests::test_dns_record_type_txt));
    suite.add(TestCase::new("dns_record_type_aaaa", dns_tests::test_dns_record_type_aaaa));
    suite.add(TestCase::new("dns_record_type_srv", dns_tests::test_dns_record_type_srv));
    suite.add(TestCase::new(
        "dns_record_type_from_u16_a",
        dns_tests::test_dns_record_type_from_u16_a,
    ));
    suite.add(TestCase::new(
        "dns_record_type_from_u16_ns",
        dns_tests::test_dns_record_type_from_u16_ns,
    ));
    suite.add(TestCase::new(
        "dns_record_type_from_u16_cname",
        dns_tests::test_dns_record_type_from_u16_cname,
    ));
    suite.add(TestCase::new(
        "dns_record_type_from_u16_soa",
        dns_tests::test_dns_record_type_from_u16_soa,
    ));
    suite.add(TestCase::new(
        "dns_record_type_from_u16_ptr",
        dns_tests::test_dns_record_type_from_u16_ptr,
    ));
    suite.add(TestCase::new(
        "dns_record_type_from_u16_mx",
        dns_tests::test_dns_record_type_from_u16_mx,
    ));
    suite.add(TestCase::new(
        "dns_record_type_from_u16_txt",
        dns_tests::test_dns_record_type_from_u16_txt,
    ));
    suite.add(TestCase::new(
        "dns_record_type_from_u16_aaaa",
        dns_tests::test_dns_record_type_from_u16_aaaa,
    ));
    suite.add(TestCase::new(
        "dns_record_type_from_u16_srv",
        dns_tests::test_dns_record_type_from_u16_srv,
    ));
    suite.add(TestCase::new(
        "dns_record_type_from_u16_invalid",
        dns_tests::test_dns_record_type_from_u16_invalid,
    ));
    suite.add(TestCase::new("dns_record_type_clone", dns_tests::test_dns_record_type_clone));
    suite.add(TestCase::new("dns_record_type_copy", dns_tests::test_dns_record_type_copy));
    suite.add(TestCase::new("dns_record_type_equality", dns_tests::test_dns_record_type_equality));
    suite.add(TestCase::new("dns_record_type_debug", dns_tests::test_dns_record_type_debug));
    suite.add(TestCase::new("dns_mx_record_fields", dns_tests::test_mx_record_fields));
    suite.add(TestCase::new("dns_mx_record_clone", dns_tests::test_mx_record_clone));
    suite.add(TestCase::new("dns_mx_record_debug", dns_tests::test_mx_record_debug));
    suite.add(TestCase::new("dns_srv_record_fields", dns_tests::test_srv_record_fields));
    suite.add(TestCase::new("dns_srv_record_clone", dns_tests::test_srv_record_clone));
    suite.add(TestCase::new("dns_record_a", dns_tests::test_dns_record_a));
    suite.add(TestCase::new("dns_record_aaaa", dns_tests::test_dns_record_aaaa));
    suite.add(TestCase::new("dns_record_cname", dns_tests::test_dns_record_cname));
    suite.add(TestCase::new("dns_record_mx", dns_tests::test_dns_record_mx));
    suite.add(TestCase::new("dns_record_txt", dns_tests::test_dns_record_txt));
    suite.add(TestCase::new("dns_record_ns", dns_tests::test_dns_record_ns));
    suite.add(TestCase::new("dns_record_ptr", dns_tests::test_dns_record_ptr));
    suite.add(TestCase::new("dns_record_srv", dns_tests::test_dns_record_srv));
    suite.add(TestCase::new("dns_record_clone", dns_tests::test_dns_record_clone));
    suite.add(TestCase::new("dns_cache_entry_fields", dns_tests::test_dns_cache_entry_fields));
    suite.add(TestCase::new(
        "dns_cache_entry_multiple_addresses",
        dns_tests::test_dns_cache_entry_multiple_addresses,
    ));
    suite.add(TestCase::new("dns_cache_entry_clone", dns_tests::test_dns_cache_entry_clone));
    suite.add(TestCase::new(
        "dns_record_cache_entry_fields",
        dns_tests::test_dns_record_cache_entry_fields,
    ));
    suite.add(TestCase::new(
        "dns_record_cache_entry_clone",
        dns_tests::test_dns_record_cache_entry_clone,
    ));
    suite.add(TestCase::new("dns_query_record_fields", dns_tests::test_dns_query_record_fields));
    suite.add(TestCase::new("dns_query_record_failed", dns_tests::test_dns_query_record_failed));
    suite.add(TestCase::new("dns_query_record_clone", dns_tests::test_dns_query_record_clone));
    suite.add(TestCase::new("dns_pending_query_fields", dns_tests::test_pending_query_fields));
    suite.add(TestCase::new("dns_pending_query_clone", dns_tests::test_pending_query_clone));
    suite.add(TestCase::new("dns_response_a_fields", dns_tests::test_dns_response_a_fields));
    suite.add(TestCase::new("dns_response_a_empty", dns_tests::test_dns_response_a_empty));
    suite.add(TestCase::new("dns_response_a_clone", dns_tests::test_dns_response_a_clone));
    suite.add(TestCase::new("dns_response_aaaa_fields", dns_tests::test_dns_response_aaaa_fields));
    suite.add(TestCase::new("dns_response_aaaa_empty", dns_tests::test_dns_response_aaaa_empty));
    suite.add(TestCase::new("dns_response_aaaa_clone", dns_tests::test_dns_response_aaaa_clone));
    suite.add(TestCase::new(
        "dns_record_type_all_values",
        dns_tests::test_dns_record_type_all_values,
    ));

    // Firewall tests (47 tests)
    suite.add(TestCase::new("firewall_action_allow", firewall_tests::test_action_allow));
    suite.add(TestCase::new("firewall_action_deny", firewall_tests::test_action_deny));
    suite.add(TestCase::new("firewall_action_drop", firewall_tests::test_action_drop));
    suite.add(TestCase::new("firewall_action_log", firewall_tests::test_action_log));
    suite.add(TestCase::new("firewall_action_rate_limit", firewall_tests::test_action_rate_limit));
    suite.add(TestCase::new("firewall_action_equality", firewall_tests::test_action_equality));
    suite.add(TestCase::new("firewall_action_clone", firewall_tests::test_action_clone));
    suite.add(TestCase::new("firewall_protocol_any", firewall_tests::test_protocol_any));
    suite.add(TestCase::new("firewall_protocol_tcp", firewall_tests::test_protocol_tcp));
    suite.add(TestCase::new("firewall_protocol_udp", firewall_tests::test_protocol_udp));
    suite.add(TestCase::new("firewall_protocol_icmp", firewall_tests::test_protocol_icmp));
    suite.add(TestCase::new("firewall_protocol_equality", firewall_tests::test_protocol_equality));
    suite.add(TestCase::new("firewall_protocol_clone", firewall_tests::test_protocol_clone));
    suite.add(TestCase::new("firewall_direction_inbound", firewall_tests::test_direction_inbound));
    suite
        .add(TestCase::new("firewall_direction_outbound", firewall_tests::test_direction_outbound));
    suite.add(TestCase::new("firewall_direction_both", firewall_tests::test_direction_both));
    suite
        .add(TestCase::new("firewall_direction_equality", firewall_tests::test_direction_equality));
    suite.add(TestCase::new("firewall_direction_clone", firewall_tests::test_direction_clone));
    suite.add(TestCase::new("firewall_ip_match_any", firewall_tests::test_ip_match_any));
    suite.add(TestCase::new("firewall_ip_match_single", firewall_tests::test_ip_match_single));
    suite.add(TestCase::new("firewall_ip_match_subnet", firewall_tests::test_ip_match_subnet));
    suite.add(TestCase::new("firewall_ip_match_range", firewall_tests::test_ip_match_range));
    suite.add(TestCase::new("firewall_ip_match_equality", firewall_tests::test_ip_match_equality));
    suite.add(TestCase::new("firewall_ip_match_clone", firewall_tests::test_ip_match_clone));
    suite.add(TestCase::new("firewall_port_match_any", firewall_tests::test_port_match_any));
    suite.add(TestCase::new("firewall_port_match_single", firewall_tests::test_port_match_single));
    suite.add(TestCase::new("firewall_port_match_range", firewall_tests::test_port_match_range));
    suite.add(TestCase::new("firewall_port_match_list", firewall_tests::test_port_match_list));
    suite.add(TestCase::new(
        "firewall_port_match_equality",
        firewall_tests::test_port_match_equality,
    ));
    suite.add(TestCase::new("firewall_port_match_clone", firewall_tests::test_port_match_clone));
    suite.add(TestCase::new("firewall_rate_limit_fields", firewall_tests::test_rate_limit_fields));
    suite.add(TestCase::new("firewall_rate_limit_clone", firewall_tests::test_rate_limit_clone));
    suite
        .add(TestCase::new("firewall_rule_stats_default", firewall_tests::test_rule_stats_default));
    suite.add(TestCase::new("firewall_rule_stats_clone", firewall_tests::test_rule_stats_clone));
    suite.add(TestCase::new("firewall_rule_fields", firewall_tests::test_rule_fields));
    suite.add(TestCase::new(
        "firewall_rule_with_rate_limit",
        firewall_tests::test_rule_with_rate_limit,
    ));
    suite.add(TestCase::new("firewall_rule_clone", firewall_tests::test_rule_clone));
    suite.add(TestCase::new("firewall_conn_state_new", firewall_tests::test_conn_state_new));
    suite.add(TestCase::new(
        "firewall_conn_state_established",
        firewall_tests::test_conn_state_established,
    ));
    suite
        .add(TestCase::new("firewall_conn_state_related", firewall_tests::test_conn_state_related));
    suite
        .add(TestCase::new("firewall_conn_state_invalid", firewall_tests::test_conn_state_invalid));
    suite.add(TestCase::new(
        "firewall_conn_state_time_wait",
        firewall_tests::test_conn_state_time_wait,
    ));
    suite.add(TestCase::new(
        "firewall_conn_state_equality",
        firewall_tests::test_conn_state_equality,
    ));
    suite.add(TestCase::new("firewall_conn_state_clone", firewall_tests::test_conn_state_clone));
    suite.add(TestCase::new("firewall_conn_track_fields", firewall_tests::test_conn_track_fields));
    suite.add(TestCase::new("firewall_conn_track_clone", firewall_tests::test_conn_track_clone));
    suite.add(TestCase::new("firewall_stats_default", firewall_tests::test_firewall_stats_default));
    suite.add(TestCase::new("firewall_format_ip", firewall_tests::test_format_ip));
    suite.add(TestCase::new("firewall_format_ip_zeros", firewall_tests::test_format_ip_zeros));
    suite.add(TestCase::new("firewall_format_ip_max", firewall_tests::test_format_ip_max));
    suite.add(TestCase::new(
        "firewall_format_ip_localhost",
        firewall_tests::test_format_ip_localhost,
    ));

    // SOCKS tests (20 tests)
    suite.add(TestCase::new(
        "socks_error_connection_failed",
        socks_tests::test_socks_error_connection_failed,
    ));
    suite.add(TestCase::new("socks_error_auth_failed", socks_tests::test_socks_error_auth_failed));
    suite.add(TestCase::new(
        "socks_error_target_unreachable",
        socks_tests::test_socks_error_target_unreachable,
    ));
    suite.add(TestCase::new("socks_error_timeout", socks_tests::test_socks_error_timeout));
    suite.add(TestCase::new(
        "socks_error_protocol_error",
        socks_tests::test_socks_error_protocol_error,
    ));
    suite.add(TestCase::new("socks_error_send_failed", socks_tests::test_socks_error_send_failed));
    suite.add(TestCase::new("socks_error_recv_failed", socks_tests::test_socks_error_recv_failed));
    suite.add(TestCase::new("socks_error_equality", socks_tests::test_socks_error_equality));
    suite.add(TestCase::new("socks_error_clone", socks_tests::test_socks_error_clone));
    suite.add(TestCase::new("socks_error_copy", socks_tests::test_socks_error_copy));
    suite.add(TestCase::new(
        "socks_error_message_connection_failed",
        socks_tests::test_error_message_connection_failed,
    ));
    suite.add(TestCase::new(
        "socks_error_message_auth_failed",
        socks_tests::test_error_message_auth_failed,
    ));
    suite.add(TestCase::new(
        "socks_error_message_target_unreachable",
        socks_tests::test_error_message_target_unreachable,
    ));
    suite
        .add(TestCase::new("socks_error_message_timeout", socks_tests::test_error_message_timeout));
    suite.add(TestCase::new(
        "socks_error_message_protocol_error",
        socks_tests::test_error_message_protocol_error,
    ));
    suite.add(TestCase::new(
        "socks_error_message_send_failed",
        socks_tests::test_error_message_send_failed,
    ));
    suite.add(TestCase::new(
        "socks_error_message_recv_failed",
        socks_tests::test_error_message_recv_failed,
    ));
    suite.add(TestCase::new(
        "socks_all_error_variants_distinct",
        socks_tests::test_all_error_variants_distinct,
    ));
    suite.add(TestCase::new(
        "socks_all_error_messages_non_empty",
        socks_tests::test_all_error_messages_non_empty,
    ));

    // Ethernet tests (35 tests)
    suite.add(TestCase::new(
        "ethernet_ethertype_ip_constant",
        ethernet_tests::test_ethertype_ip_constant,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_ipv6_constant",
        ethernet_tests::test_ethertype_ipv6_constant,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_arp_constant",
        ethernet_tests::test_ethertype_arp_constant,
    ));
    suite.add(TestCase::new("ethernet_ethertypes_unique", ethernet_tests::test_ethertypes_unique));
    suite.add(TestCase::new(
        "ethernet_ethertype_ipv4_variant",
        ethernet_tests::test_ethertype_ipv4_variant,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_ipv6_variant",
        ethernet_tests::test_ethertype_ipv6_variant,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_arp_variant",
        ethernet_tests::test_ethertype_arp_variant,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_other_variant",
        ethernet_tests::test_ethertype_other_variant,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_from_u16_ipv4",
        ethernet_tests::test_ethertype_from_u16_ipv4,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_from_u16_ipv6",
        ethernet_tests::test_ethertype_from_u16_ipv6,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_from_u16_arp",
        ethernet_tests::test_ethertype_from_u16_arp,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_from_u16_other",
        ethernet_tests::test_ethertype_from_u16_other,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_from_u16_zero",
        ethernet_tests::test_ethertype_from_u16_zero,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_to_u16_ipv4",
        ethernet_tests::test_ethertype_to_u16_ipv4,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_to_u16_ipv6",
        ethernet_tests::test_ethertype_to_u16_ipv6,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_to_u16_arp",
        ethernet_tests::test_ethertype_to_u16_arp,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_to_u16_other",
        ethernet_tests::test_ethertype_to_u16_other,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_roundtrip_ipv4",
        ethernet_tests::test_ethertype_roundtrip_ipv4,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_roundtrip_ipv6",
        ethernet_tests::test_ethertype_roundtrip_ipv6,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_roundtrip_arp",
        ethernet_tests::test_ethertype_roundtrip_arp,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_roundtrip_other",
        ethernet_tests::test_ethertype_roundtrip_other,
    ));
    suite.add(TestCase::new("ethernet_ethertype_clone", ethernet_tests::test_ethertype_clone));
    suite.add(TestCase::new("ethernet_ethertype_copy", ethernet_tests::test_ethertype_copy));
    suite
        .add(TestCase::new("ethernet_ethertype_equality", ethernet_tests::test_ethertype_equality));
    suite.add(TestCase::new(
        "ethernet_ethertype_inequality",
        ethernet_tests::test_ethertype_inequality,
    ));
    suite.add(TestCase::new("ethernet_ethertype_debug", ethernet_tests::test_ethertype_debug));
    suite.add(TestCase::new(
        "ethernet_ethertype_debug_other",
        ethernet_tests::test_ethertype_debug_other,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_all_known_values",
        ethernet_tests::test_ethertype_all_known_values,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_from_all_known_values",
        ethernet_tests::test_ethertype_from_all_known_values,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_max_value",
        ethernet_tests::test_ethertype_max_value,
    ));
    suite.add(TestCase::new(
        "ethernet_ethertype_common_protocols",
        ethernet_tests::test_ethertype_common_protocols,
    ));

    // HTTP tests (45 tests)
    suite.add(TestCase::new("http_method_get", http_tests::test_http_method_get));
    suite.add(TestCase::new("http_method_head", http_tests::test_http_method_head));
    suite.add(TestCase::new("http_method_post", http_tests::test_http_method_post));
    suite.add(TestCase::new("http_method_put", http_tests::test_http_method_put));
    suite.add(TestCase::new("http_method_delete", http_tests::test_http_method_delete));
    suite.add(TestCase::new("http_method_clone", http_tests::test_http_method_clone));
    suite.add(TestCase::new("http_method_copy", http_tests::test_http_method_copy));
    suite.add(TestCase::new("http_method_equality", http_tests::test_http_method_equality));
    suite.add(TestCase::new("http_method_debug", http_tests::test_http_method_debug));
    suite.add(TestCase::new(
        "http_request_options_default",
        http_tests::test_http_request_options_default,
    ));
    suite.add(TestCase::new(
        "http_request_options_with_method",
        http_tests::test_http_request_options_with_method,
    ));
    suite.add(TestCase::new(
        "http_request_options_with_headers",
        http_tests::test_http_request_options_with_headers,
    ));
    suite.add(TestCase::new(
        "http_request_options_with_body",
        http_tests::test_http_request_options_with_body,
    ));
    suite.add(TestCase::new(
        "http_request_options_no_redirects",
        http_tests::test_http_request_options_no_redirects,
    ));
    suite.add(TestCase::new(
        "http_request_options_custom_timeout",
        http_tests::test_http_request_options_custom_timeout,
    ));
    suite.add(TestCase::new(
        "http_request_options_verbose",
        http_tests::test_http_request_options_verbose,
    ));
    suite.add(TestCase::new(
        "http_request_options_no_keep_alive",
        http_tests::test_http_request_options_no_keep_alive,
    ));
    suite.add(TestCase::new(
        "http_request_options_no_cookies",
        http_tests::test_http_request_options_no_cookies,
    ));
    suite.add(TestCase::new(
        "http_request_options_clone",
        http_tests::test_http_request_options_clone,
    ));
    suite.add(TestCase::new("http_response_new", http_tests::test_http_response_new));
    suite.add(TestCase::new("http_response_success", http_tests::test_http_response_success));
    suite.add(TestCase::new(
        "http_response_success_range",
        http_tests::test_http_response_success_range,
    ));
    suite.add(TestCase::new(
        "http_response_not_success",
        http_tests::test_http_response_not_success,
    ));
    suite.add(TestCase::new(
        "http_response_redirect_301",
        http_tests::test_http_response_redirect_301,
    ));
    suite.add(TestCase::new(
        "http_response_redirect_302",
        http_tests::test_http_response_redirect_302,
    ));
    suite.add(TestCase::new(
        "http_response_redirect_303",
        http_tests::test_http_response_redirect_303,
    ));
    suite.add(TestCase::new(
        "http_response_redirect_307",
        http_tests::test_http_response_redirect_307,
    ));
    suite.add(TestCase::new(
        "http_response_redirect_308",
        http_tests::test_http_response_redirect_308,
    ));
    suite.add(TestCase::new(
        "http_response_not_redirect",
        http_tests::test_http_response_not_redirect,
    ));
    suite.add(TestCase::new(
        "http_response_header_found",
        http_tests::test_http_response_header_found,
    ));
    suite.add(TestCase::new(
        "http_response_header_not_found",
        http_tests::test_http_response_header_not_found,
    ));
    suite.add(TestCase::new(
        "http_response_content_length",
        http_tests::test_http_response_content_length,
    ));
    suite.add(TestCase::new(
        "http_response_content_length_none",
        http_tests::test_http_response_content_length_none,
    ));
    suite.add(TestCase::new(
        "http_response_content_type",
        http_tests::test_http_response_content_type,
    ));
    suite.add(TestCase::new("http_response_location", http_tests::test_http_response_location));
    suite.add(TestCase::new("http_response_body_text", http_tests::test_http_response_body_text));
    suite.add(TestCase::new(
        "http_response_body_text_invalid_utf8",
        http_tests::test_http_response_body_text_invalid_utf8,
    ));
    suite.add(TestCase::new(
        "http_response_is_keep_alive_true",
        http_tests::test_http_response_is_keep_alive_true,
    ));
    suite.add(TestCase::new(
        "http_response_is_keep_alive_false",
        http_tests::test_http_response_is_keep_alive_false,
    ));
    suite.add(TestCase::new(
        "http_response_is_keep_alive_no_header",
        http_tests::test_http_response_is_keep_alive_no_header,
    ));
    suite.add(TestCase::new(
        "http_response_set_cookie_headers",
        http_tests::test_http_response_set_cookie_headers,
    ));
    suite.add(TestCase::new(
        "http_response_no_set_cookie_headers",
        http_tests::test_http_response_no_set_cookie_headers,
    ));
    suite.add(TestCase::new("http_response_clone", http_tests::test_http_response_clone));
    suite.add(TestCase::new("http_response_debug", http_tests::test_http_response_debug));
    suite.add(TestCase::new("http_method_all_variants", http_tests::test_http_method_all_variants));

    // Boot config tests (42 tests)
    suite.add(TestCase::new(
        "boot_config_privacy_mode_standard",
        boot_config_tests::test_privacy_mode_standard,
    ));
    suite.add(TestCase::new(
        "boot_config_privacy_mode_tor_only",
        boot_config_tests::test_privacy_mode_tor_only,
    ));
    suite.add(TestCase::new(
        "boot_config_privacy_mode_maximum",
        boot_config_tests::test_privacy_mode_maximum,
    ));
    suite.add(TestCase::new(
        "boot_config_privacy_mode_isolated",
        boot_config_tests::test_privacy_mode_isolated,
    ));
    suite.add(TestCase::new(
        "boot_config_privacy_mode_from_u8_standard",
        boot_config_tests::test_privacy_mode_from_u8_standard,
    ));
    suite.add(TestCase::new(
        "boot_config_privacy_mode_from_u8_tor_only",
        boot_config_tests::test_privacy_mode_from_u8_tor_only,
    ));
    suite.add(TestCase::new(
        "boot_config_privacy_mode_from_u8_maximum",
        boot_config_tests::test_privacy_mode_from_u8_maximum,
    ));
    suite.add(TestCase::new(
        "boot_config_privacy_mode_from_u8_isolated",
        boot_config_tests::test_privacy_mode_from_u8_isolated,
    ));
    suite.add(TestCase::new(
        "boot_config_privacy_mode_from_u8_invalid",
        boot_config_tests::test_privacy_mode_from_u8_invalid,
    ));
    suite.add(TestCase::new(
        "boot_config_privacy_mode_clone",
        boot_config_tests::test_privacy_mode_clone,
    ));
    suite.add(TestCase::new(
        "boot_config_privacy_mode_copy",
        boot_config_tests::test_privacy_mode_copy,
    ));
    suite.add(TestCase::new(
        "boot_config_privacy_mode_equality",
        boot_config_tests::test_privacy_mode_equality,
    ));
    suite.add(TestCase::new(
        "boot_config_privacy_mode_debug",
        boot_config_tests::test_privacy_mode_debug,
    ));
    suite.add(TestCase::new("boot_config_dns_mode_dhcp", boot_config_tests::test_dns_mode_dhcp));
    suite
        .add(TestCase::new("boot_config_dns_mode_custom", boot_config_tests::test_dns_mode_custom));
    suite.add(TestCase::new(
        "boot_config_dns_mode_tor_dns",
        boot_config_tests::test_dns_mode_tor_dns,
    ));
    suite.add(TestCase::new("boot_config_dns_mode_doh", boot_config_tests::test_dns_mode_doh));
    suite.add(TestCase::new("boot_config_dns_mode_none", boot_config_tests::test_dns_mode_none));
    suite.add(TestCase::new("boot_config_dns_mode_clone", boot_config_tests::test_dns_mode_clone));
    suite.add(TestCase::new("boot_config_dns_mode_copy", boot_config_tests::test_dns_mode_copy));
    suite.add(TestCase::new(
        "boot_config_dns_mode_equality",
        boot_config_tests::test_dns_mode_equality,
    ));
    suite.add(TestCase::new("boot_config_dns_mode_debug", boot_config_tests::test_dns_mode_debug));
    suite.add(TestCase::new(
        "boot_config_ipv4_config_default",
        boot_config_tests::test_ipv4_config_default,
    ));
    suite.add(TestCase::new(
        "boot_config_ipv4_config_fields",
        boot_config_tests::test_ipv4_config_fields,
    ));
    suite.add(TestCase::new(
        "boot_config_ipv4_config_clone",
        boot_config_tests::test_ipv4_config_clone,
    ));
    suite.add(TestCase::new(
        "boot_config_ipv4_config_no_gateway",
        boot_config_tests::test_ipv4_config_no_gateway,
    ));
    suite.add(TestCase::new(
        "boot_config_onion_config_default",
        boot_config_tests::test_onion_config_default,
    ));
    suite.add(TestCase::new(
        "boot_config_onion_config_fields",
        boot_config_tests::test_onion_config_fields,
    ));
    suite.add(TestCase::new(
        "boot_config_onion_config_clone",
        boot_config_tests::test_onion_config_clone,
    ));
    suite.add(TestCase::new(
        "boot_config_firewall_config_default",
        boot_config_tests::test_firewall_config_default,
    ));
    suite.add(TestCase::new(
        "boot_config_firewall_config_fields",
        boot_config_tests::test_firewall_config_fields,
    ));
    suite.add(TestCase::new(
        "boot_config_firewall_config_clone",
        boot_config_tests::test_firewall_config_clone,
    ));
    suite.add(TestCase::new(
        "boot_config_firewall_config_blocked_range",
        boot_config_tests::test_firewall_config_blocked_range,
    ));
    suite.add(TestCase::new(
        "boot_config_network_boot_config_default",
        boot_config_tests::test_network_boot_config_default,
    ));
    suite.add(TestCase::new(
        "boot_config_network_boot_config_fields",
        boot_config_tests::test_network_boot_config_fields,
    ));
    suite.add(TestCase::new(
        "boot_config_network_boot_config_clone",
        boot_config_tests::test_network_boot_config_clone,
    ));
    suite.add(TestCase::new(
        "boot_config_network_boot_config_isolated",
        boot_config_tests::test_network_boot_config_isolated,
    ));
    suite.add(TestCase::new(
        "boot_config_network_boot_config_tor_mode",
        boot_config_tests::test_network_boot_config_tor_mode,
    ));
    suite.add(TestCase::new(
        "boot_config_privacy_mode_all_variants",
        boot_config_tests::test_privacy_mode_all_variants,
    ));
    suite.add(TestCase::new(
        "boot_config_dns_mode_all_variants",
        boot_config_tests::test_dns_mode_all_variants,
    ));
    suite.add(TestCase::new(
        "boot_config_ipv4_config_debug",
        boot_config_tests::test_ipv4_config_debug,
    ));
    suite.add(TestCase::new(
        "boot_config_onion_config_debug",
        boot_config_tests::test_onion_config_debug,
    ));
    suite.add(TestCase::new(
        "boot_config_firewall_config_debug",
        boot_config_tests::test_firewall_config_debug,
    ));
    suite.add(TestCase::new(
        "boot_config_network_boot_config_debug",
        boot_config_tests::test_network_boot_config_debug,
    ));

    // NYM tests (72 tests)
    suite.add(TestCase::new("nym_packet_size", nym_tests::test_nym_packet_size));
    suite.add(TestCase::new("nym_payload_size", nym_tests::test_nym_payload_size));
    suite.add(TestCase::new("nym_header_size", nym_tests::test_nym_header_size));
    suite.add(TestCase::new("nym_mac_size", nym_tests::test_nym_mac_size));
    suite.add(TestCase::new("nym_routing_info_size", nym_tests::test_nym_routing_info_size));
    suite.add(TestCase::new("nym_mix_layers", nym_tests::test_nym_mix_layers));
    suite.add(TestCase::new("nym_cover_interval_ms", nym_tests::test_nym_cover_interval_ms));
    suite.add(TestCase::new("nym_key_size", nym_tests::test_nym_key_size));
    suite.add(TestCase::new("nym_nonce_size", nym_tests::test_nym_nonce_size));
    suite.add(TestCase::new("nym_tag_size", nym_tests::test_nym_tag_size));
    suite.add(TestCase::new("nym_node_address_size", nym_tests::test_nym_node_address_size));
    suite.add(TestCase::new("nym_surb_size", nym_tests::test_nym_surb_size));
    suite.add(TestCase::new("nym_fragment_size", nym_tests::test_nym_fragment_size));
    suite.add(TestCase::new("nym_max_hops", nym_tests::test_nym_max_hops));
    suite.add(TestCase::new("nym_default_gateway_port", nym_tests::test_nym_default_gateway_port));
    suite.add(TestCase::new("nym_default_mix_port", nym_tests::test_nym_default_mix_port));
    suite.add(TestCase::new("nym_connect_timeout_ms", nym_tests::test_nym_connect_timeout_ms));
    suite.add(TestCase::new("nym_read_timeout_ms", nym_tests::test_nym_read_timeout_ms));
    suite.add(TestCase::new("nym_write_timeout_ms", nym_tests::test_nym_write_timeout_ms));
    suite.add(TestCase::new("nym_packet_structure", nym_tests::test_nym_packet_structure));
    suite.add(TestCase::new(
        "nym_max_hops_equals_mix_layers",
        nym_tests::test_nym_max_hops_equals_mix_layers,
    ));
    suite.add(TestCase::new("nym_mixnode_id_from_bytes", nym_tests::test_mixnode_id_from_bytes));
    suite.add(TestCase::new(
        "nym_mixnode_id_from_bytes_wrong_size",
        nym_tests::test_mixnode_id_from_bytes_wrong_size,
    ));
    suite.add(TestCase::new("nym_mixnode_id_as_bytes", nym_tests::test_mixnode_id_as_bytes));
    suite.add(TestCase::new("nym_mixnode_id_clone", nym_tests::test_mixnode_id_clone));
    suite.add(TestCase::new("nym_mixnode_id_copy", nym_tests::test_mixnode_id_copy));
    suite.add(TestCase::new("nym_mixnode_id_equality", nym_tests::test_mixnode_id_equality));
    suite.add(TestCase::new("nym_mixnode_id_ordering", nym_tests::test_mixnode_id_ordering));
    suite.add(TestCase::new("nym_gateway_id_from_bytes", nym_tests::test_gateway_id_from_bytes));
    suite.add(TestCase::new(
        "nym_gateway_id_from_bytes_wrong_size",
        nym_tests::test_gateway_id_from_bytes_wrong_size,
    ));
    suite.add(TestCase::new("nym_gateway_id_as_bytes", nym_tests::test_gateway_id_as_bytes));
    suite.add(TestCase::new("nym_gateway_id_clone", nym_tests::test_gateway_id_clone));
    suite.add(TestCase::new("nym_gateway_id_copy", nym_tests::test_gateway_id_copy));
    suite.add(TestCase::new("nym_gateway_id_equality", nym_tests::test_gateway_id_equality));
    suite.add(TestCase::new("nym_client_id_from_bytes", nym_tests::test_client_id_from_bytes));
    suite.add(TestCase::new(
        "nym_client_id_from_bytes_wrong_size",
        nym_tests::test_client_id_from_bytes_wrong_size,
    ));
    suite.add(TestCase::new("nym_client_id_as_bytes", nym_tests::test_client_id_as_bytes));
    suite.add(TestCase::new("nym_client_id_clone", nym_tests::test_client_id_clone));
    suite.add(TestCase::new("nym_client_id_copy", nym_tests::test_client_id_copy));
    suite.add(TestCase::new("nym_surb_id_from_bytes", nym_tests::test_surb_id_from_bytes));
    suite.add(TestCase::new(
        "nym_surb_id_from_bytes_wrong_size",
        nym_tests::test_surb_id_from_bytes_wrong_size,
    ));
    suite.add(TestCase::new("nym_surb_id_as_bytes", nym_tests::test_surb_id_as_bytes));
    suite.add(TestCase::new("nym_surb_id_clone", nym_tests::test_surb_id_clone));
    suite.add(TestCase::new("nym_surb_id_copy", nym_tests::test_surb_id_copy));
    suite.add(TestCase::new("nym_address_new", nym_tests::test_nym_address_new));
    suite.add(TestCase::new("nym_address_to_bytes", nym_tests::test_nym_address_to_bytes));
    suite.add(TestCase::new("nym_address_from_bytes", nym_tests::test_nym_address_from_bytes));
    suite.add(TestCase::new(
        "nym_address_from_bytes_wrong_size",
        nym_tests::test_nym_address_from_bytes_wrong_size,
    ));
    suite.add(TestCase::new("nym_address_roundtrip", nym_tests::test_nym_address_roundtrip));
    suite.add(TestCase::new("nym_address_clone", nym_tests::test_nym_address_clone));
    suite.add(TestCase::new("nym_address_equality", nym_tests::test_nym_address_equality));
    suite
        .add(TestCase::new("nym_error_not_initialized", nym_tests::test_nym_error_not_initialized));
    suite.add(TestCase::new(
        "nym_error_already_initialized",
        nym_tests::test_nym_error_already_initialized,
    ));
    suite.add(TestCase::new(
        "nym_error_connection_failed",
        nym_tests::test_nym_error_connection_failed,
    ));
    suite.add(TestCase::new("nym_error_not_connected", nym_tests::test_nym_error_not_connected));
    suite.add(TestCase::new(
        "nym_error_handshake_failed",
        nym_tests::test_nym_error_handshake_failed,
    ));
    suite.add(TestCase::new("nym_error_send_failed", nym_tests::test_nym_error_send_failed));
    suite.add(TestCase::new("nym_error_receive_failed", nym_tests::test_nym_error_receive_failed));
    suite.add(TestCase::new(
        "nym_error_gateway_not_found",
        nym_tests::test_nym_error_gateway_not_found,
    ));
    suite.add(TestCase::new(
        "nym_error_mixnode_not_found",
        nym_tests::test_nym_error_mixnode_not_found,
    ));
    suite.add(TestCase::new("nym_error_invalid_route", nym_tests::test_nym_error_invalid_route));
    suite.add(TestCase::new("nym_error_invalid_packet", nym_tests::test_nym_error_invalid_packet));
    suite.add(TestCase::new(
        "nym_error_packet_too_large",
        nym_tests::test_nym_error_packet_too_large,
    ));
    suite.add(TestCase::new(
        "nym_error_encryption_failed",
        nym_tests::test_nym_error_encryption_failed,
    ));
    suite.add(TestCase::new(
        "nym_error_decryption_failed",
        nym_tests::test_nym_error_decryption_failed,
    ));
    suite.add(TestCase::new("nym_error_invalid_mac", nym_tests::test_nym_error_invalid_mac));
    suite.add(TestCase::new("nym_error_invalid_header", nym_tests::test_nym_error_invalid_header));
    suite
        .add(TestCase::new("nym_error_invalid_payload", nym_tests::test_nym_error_invalid_payload));
    suite.add(TestCase::new("nym_error_invalid_surb", nym_tests::test_nym_error_invalid_surb));
    suite.add(TestCase::new(
        "nym_error_no_available_mixnodes",
        nym_tests::test_nym_error_no_available_mixnodes,
    ));
    suite.add(TestCase::new(
        "nym_error_no_available_gateways",
        nym_tests::test_nym_error_no_available_gateways,
    ));
    suite.add(TestCase::new(
        "nym_error_directory_fetch_failed",
        nym_tests::test_nym_error_directory_fetch_failed,
    ));
    suite.add(TestCase::new("nym_error_timeout", nym_tests::test_nym_error_timeout));
    suite.add(TestCase::new("nym_error_socket_error", nym_tests::test_nym_error_socket_error));
    suite.add(TestCase::new("nym_error_tls_error", nym_tests::test_nym_error_tls_error));
    suite
        .add(TestCase::new("nym_error_invalid_address", nym_tests::test_nym_error_invalid_address));
    suite.add(TestCase::new("nym_error_stream_closed", nym_tests::test_nym_error_stream_closed));
    suite.add(TestCase::new("nym_error_buffer_full", nym_tests::test_nym_error_buffer_full));
    suite.add(TestCase::new("nym_error_internal_error", nym_tests::test_nym_error_internal_error));
    suite.add(TestCase::new("nym_error_clone", nym_tests::test_nym_error_clone));
    suite.add(TestCase::new("nym_error_copy", nym_tests::test_nym_error_copy));
    suite.add(TestCase::new("nym_error_equality", nym_tests::test_nym_error_equality));
    suite.add(TestCase::new("nym_error_debug", nym_tests::test_nym_error_debug));
    suite.add(TestCase::new("nym_error_all_have_str", nym_tests::test_nym_error_all_have_str));

    // Stack tests (28 tests)
    suite.add(TestCase::new("stack_tcp_socket_new", stack_tests::test_tcp_socket_new));
    suite.add(TestCase::new("stack_tcp_socket_default", stack_tests::test_tcp_socket_default));
    suite.add(TestCase::new(
        "stack_tcp_socket_from_connection",
        stack_tests::test_tcp_socket_from_connection,
    ));
    suite.add(TestCase::new(
        "stack_tcp_socket_remote_port",
        stack_tests::test_tcp_socket_remote_port,
    ));
    suite.add(TestCase::new("stack_tcp_socket_clone", stack_tests::test_tcp_socket_clone));
    suite.add(TestCase::new(
        "stack_tcp_socket_increments_id",
        stack_tests::test_tcp_socket_increments_id,
    ));
    suite.add(TestCase::new("stack_socket_new", stack_tests::test_socket_new));
    suite.add(TestCase::new("stack_socket_default", stack_tests::test_socket_default));
    suite
        .add(TestCase::new("stack_socket_for_connection", stack_tests::test_socket_for_connection));
    suite.add(TestCase::new("stack_socket_clone", stack_tests::test_socket_clone));
    suite
        .add(TestCase::new("stack_network_stats_default", stack_tests::test_network_stats_default));
    suite.add(TestCase::new("stack_network_stats_fields", stack_tests::test_network_stats_fields));
    suite.add(TestCase::new("stack_network_stats_clone", stack_tests::test_network_stats_clone));
    suite.add(TestCase::new("stack_arp_entry_fields", stack_tests::test_arp_entry_fields));
    suite.add(TestCase::new("stack_arp_entry_clone", stack_tests::test_arp_entry_clone));
    suite.add(TestCase::new("stack_socket_info_fields", stack_tests::test_socket_info_fields));
    suite.add(TestCase::new("stack_socket_info_udp", stack_tests::test_socket_info_udp));
    suite.add(TestCase::new("stack_socket_info_closed", stack_tests::test_socket_info_closed));
    suite.add(TestCase::new(
        "stack_socket_info_with_error",
        stack_tests::test_socket_info_with_error,
    ));
    suite.add(TestCase::new("stack_socket_info_clone", stack_tests::test_socket_info_clone));
    suite.add(TestCase::new("stack_dhcp_lease_fields", stack_tests::test_dhcp_lease_fields));
    suite
        .add(TestCase::new("stack_dhcp_lease_short_time", stack_tests::test_dhcp_lease_short_time));
    suite.add(TestCase::new("stack_dhcp_lease_clone", stack_tests::test_dhcp_lease_clone));
    suite.add(TestCase::new("stack_dhcp_lease_infinite", stack_tests::test_dhcp_lease_infinite));

    suite.run()
}
