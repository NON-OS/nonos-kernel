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

extern crate alloc;

use super::framework::{TestCase, TestResult, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("Network");

    suite.add(TestCase::new("ipv4_address_parsing", test_ipv4_address_parsing, "network"));
    suite.add(TestCase::new("ipv4_address_format", test_ipv4_address_format, "network"));
    suite.add(TestCase::new("mac_address_parsing", test_mac_address_parsing, "network"));
    suite.add(TestCase::new("ethernet_frame_types", test_ethernet_frame_types, "network"));
    suite.add(TestCase::new("tcp_state_machine", test_tcp_state_machine, "network"));
    suite.add(TestCase::new("udp_header_construction", test_udp_header_construction, "network"));
    suite.add(TestCase::new("dns_query_construction", test_dns_query_construction, "network"));
    suite.add(TestCase::new("firewall_rule_matching", test_firewall_rule_matching, "network"));

    let (_, failed, _) = suite.run_all();
    failed == 0
}

pub(crate) fn test_ipv4_address_parsing() -> TestResult {
    use crate::network::ip::Ipv4Addr;

    let addr = Ipv4Addr::new(192, 168, 1, 1);
    if addr.octets() != [192, 168, 1, 1] {
        return TestResult::Fail;
    }

    let localhost = Ipv4Addr::new(127, 0, 0, 1);
    if !localhost.is_loopback() {
        return TestResult::Fail;
    }

    let broadcast = Ipv4Addr::new(255, 255, 255, 255);
    if !broadcast.is_broadcast() {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_ipv4_address_format() -> TestResult {
    use crate::network::ip::Ipv4Addr;

    let addr = Ipv4Addr::new(10, 0, 0, 1);
    if !addr.is_private() {
        return TestResult::Fail;
    }

    let public = Ipv4Addr::new(8, 8, 8, 8);
    if public.is_private() {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_mac_address_parsing() -> TestResult {
    use crate::network::ethernet::MacAddress;

    let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    if mac.octets() != [0x00, 0x11, 0x22, 0x33, 0x44, 0x55] {
        return TestResult::Fail;
    }

    let broadcast = MacAddress::broadcast();
    if broadcast.octets() != [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] {
        return TestResult::Fail;
    }

    if !broadcast.is_broadcast() {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_ethernet_frame_types() -> TestResult {
    use crate::network::ethernet::EtherType;

    if EtherType::Ipv4 as u16 != 0x0800 {
        return TestResult::Fail;
    }
    if EtherType::Ipv6 as u16 != 0x86DD {
        return TestResult::Fail;
    }
    if EtherType::Arp as u16 != 0x0806 {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_tcp_state_machine() -> TestResult {
    use crate::network::tcp::TcpState;

    let state = TcpState::Closed;
    if state != TcpState::Closed {
        return TestResult::Fail;
    }

    let listen = TcpState::Listen;
    if listen == TcpState::Closed {
        return TestResult::Fail;
    }

    let established = TcpState::Established;
    if established != TcpState::Established {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_udp_header_construction() -> TestResult {
    use crate::network::udp::UdpHeader;

    let header = UdpHeader::new(12345, 80, 100);

    if header.src_port() != 12345 {
        return TestResult::Fail;
    }
    if header.dst_port() != 80 {
        return TestResult::Fail;
    }
    if header.length() != 100 {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_dns_query_construction() -> TestResult {
    use crate::network::dns::{DnsQuery, QueryType};

    let query = DnsQuery::new(b"example.com", QueryType::A);

    if query.name() != b"example.com" {
        return TestResult::Fail;
    }
    if query.query_type() != QueryType::A {
        return TestResult::Fail;
    }

    let aaaa_query = DnsQuery::new(b"test.org", QueryType::AAAA);
    if aaaa_query.query_type() != QueryType::AAAA {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_firewall_rule_matching() -> TestResult {
    use crate::network::firewall::{Action, FirewallRule, Protocol};
    use crate::network::ip::Ipv4Addr;

    let rule = FirewallRule::new(
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(0, 0, 0, 0),
        Protocol::Tcp,
        80,
        Action::Allow,
    );

    if rule.action() != Action::Allow {
        return TestResult::Fail;
    }
    if rule.protocol() != Protocol::Tcp {
        return TestResult::Fail;
    }
    if rule.port() != 80 {
        return TestResult::Fail;
    }

    TestResult::Pass
}
