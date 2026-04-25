// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Firewall type and rule tests

use crate::network::firewall::types::{
    format_ip, Action, ConnState, ConnTrack, Direction, FirewallStats, IpMatch, PortMatch,
    Protocol, RateLimit, Rule, RuleStats,
};
use crate::test::framework::TestResult;
use alloc::string::String;
use core::sync::atomic::Ordering;

pub(crate) fn test_action_allow() -> TestResult {
    let action = Action::Allow;
    if action != Action::Allow {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_action_deny() -> TestResult {
    let action = Action::Deny;
    if action != Action::Deny {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_action_drop() -> TestResult {
    let action = Action::Drop;
    if action != Action::Drop {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_action_log() -> TestResult {
    let action = Action::Log;
    if action != Action::Log {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_action_rate_limit() -> TestResult {
    let action = Action::RateLimit;
    if action != Action::RateLimit {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_action_equality() -> TestResult {
    if Action::Allow != Action::Allow {
        return TestResult::Fail;
    }
    if Action::Allow == Action::Deny {
        return TestResult::Fail;
    }
    if Action::Drop == Action::Log {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_action_clone() -> TestResult {
    let action = Action::Deny;
    let cloned = action.clone();
    if action != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_protocol_any() -> TestResult {
    let proto = Protocol::Any;
    if proto != Protocol::Any {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_protocol_tcp() -> TestResult {
    let proto = Protocol::Tcp;
    if proto != Protocol::Tcp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_protocol_udp() -> TestResult {
    let proto = Protocol::Udp;
    if proto != Protocol::Udp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_protocol_icmp() -> TestResult {
    let proto = Protocol::Icmp;
    if proto != Protocol::Icmp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_protocol_equality() -> TestResult {
    if Protocol::Tcp != Protocol::Tcp {
        return TestResult::Fail;
    }
    if Protocol::Tcp == Protocol::Udp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_protocol_clone() -> TestResult {
    let proto = Protocol::Icmp;
    let cloned = proto.clone();
    if proto != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_direction_inbound() -> TestResult {
    let dir = Direction::Inbound;
    if dir != Direction::Inbound {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_direction_outbound() -> TestResult {
    let dir = Direction::Outbound;
    if dir != Direction::Outbound {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_direction_both() -> TestResult {
    let dir = Direction::Both;
    if dir != Direction::Both {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_direction_equality() -> TestResult {
    if Direction::Inbound != Direction::Inbound {
        return TestResult::Fail;
    }
    if Direction::Inbound == Direction::Outbound {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_direction_clone() -> TestResult {
    let dir = Direction::Both;
    let cloned = dir.clone();
    if dir != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_match_any() -> TestResult {
    let m = IpMatch::Any;
    if m != IpMatch::Any {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_match_single() -> TestResult {
    let m = IpMatch::Single([192, 168, 1, 1]);
    if let IpMatch::Single(addr) = m {
        if addr != [192, 168, 1, 1] {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_match_subnet() -> TestResult {
    let m = IpMatch::Subnet([192, 168, 0, 0], 16);
    if let IpMatch::Subnet(addr, prefix) = m {
        if addr != [192, 168, 0, 0] {
            return TestResult::Fail;
        }
        if prefix != 16 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_match_range() -> TestResult {
    let m = IpMatch::Range([10, 0, 0, 1], [10, 0, 0, 255]);
    if let IpMatch::Range(start, end) = m {
        if start != [10, 0, 0, 1] {
            return TestResult::Fail;
        }
        if end != [10, 0, 0, 255] {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_match_equality() -> TestResult {
    if IpMatch::Any != IpMatch::Any {
        return TestResult::Fail;
    }
    if IpMatch::Single([1, 2, 3, 4]) != IpMatch::Single([1, 2, 3, 4]) {
        return TestResult::Fail;
    }
    if IpMatch::Single([1, 2, 3, 4]) == IpMatch::Single([1, 2, 3, 5]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_match_clone() -> TestResult {
    let m = IpMatch::Subnet([172, 16, 0, 0], 12);
    let cloned = m.clone();
    if m != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_match_any() -> TestResult {
    let m = PortMatch::Any;
    if m != PortMatch::Any {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_match_single() -> TestResult {
    let m = PortMatch::Single(80);
    if let PortMatch::Single(port) = m {
        if port != 80 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_match_range() -> TestResult {
    let m = PortMatch::Range(1024, 65535);
    if let PortMatch::Range(start, end) = m {
        if start != 1024 {
            return TestResult::Fail;
        }
        if end != 65535 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_match_list() -> TestResult {
    let m = PortMatch::List([80, 443, 8080, 8443, 0, 0, 0, 0], 4);
    if let PortMatch::List(ports, count) = m {
        if count != 4 {
            return TestResult::Fail;
        }
        if ports[0] != 80 {
            return TestResult::Fail;
        }
        if ports[1] != 443 {
            return TestResult::Fail;
        }
        if ports[2] != 8080 {
            return TestResult::Fail;
        }
        if ports[3] != 8443 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_match_equality() -> TestResult {
    if PortMatch::Any != PortMatch::Any {
        return TestResult::Fail;
    }
    if PortMatch::Single(443) != PortMatch::Single(443) {
        return TestResult::Fail;
    }
    if PortMatch::Single(80) == PortMatch::Single(443) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_match_clone() -> TestResult {
    let m = PortMatch::Range(1, 1023);
    let cloned = m.clone();
    if m != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rate_limit_fields() -> TestResult {
    let rl = RateLimit { packets_per_second: 100, burst_size: 10 };
    if rl.packets_per_second != 100 {
        return TestResult::Fail;
    }
    if rl.burst_size != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rate_limit_clone() -> TestResult {
    let rl = RateLimit { packets_per_second: 1000, burst_size: 50 };
    let cloned = rl.clone();
    if rl.packets_per_second != cloned.packets_per_second {
        return TestResult::Fail;
    }
    if rl.burst_size != cloned.burst_size {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rule_stats_default() -> TestResult {
    let stats = RuleStats::default();
    if stats.matches.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if stats.bytes.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if stats.last_match_ms.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rule_stats_clone() -> TestResult {
    let stats = RuleStats::default();
    stats.matches.store(100, Ordering::Relaxed);
    stats.bytes.store(5000, Ordering::Relaxed);
    stats.last_match_ms.store(1000, Ordering::Relaxed);

    let cloned = stats.clone();
    if cloned.matches.load(Ordering::Relaxed) != 100 {
        return TestResult::Fail;
    }
    if cloned.bytes.load(Ordering::Relaxed) != 5000 {
        return TestResult::Fail;
    }
    if cloned.last_match_ms.load(Ordering::Relaxed) != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rule_fields() -> TestResult {
    let rule = Rule {
        id: 1,
        name: String::from("Allow HTTP"),
        enabled: true,
        priority: 100,
        action: Action::Allow,
        direction: Direction::Outbound,
        protocol: Protocol::Tcp,
        src_ip: IpMatch::Any,
        dst_ip: IpMatch::Any,
        src_port: PortMatch::Any,
        dst_port: PortMatch::Single(80),
        rate_limit: None,
        log: false,
        stats: RuleStats::default(),
    };
    if rule.id != 1 {
        return TestResult::Fail;
    }
    if rule.name != "Allow HTTP" {
        return TestResult::Fail;
    }
    if !rule.enabled {
        return TestResult::Fail;
    }
    if rule.priority != 100 {
        return TestResult::Fail;
    }
    if rule.action != Action::Allow {
        return TestResult::Fail;
    }
    if rule.direction != Direction::Outbound {
        return TestResult::Fail;
    }
    if rule.protocol != Protocol::Tcp {
        return TestResult::Fail;
    }
    if rule.rate_limit.is_some() {
        return TestResult::Fail;
    }
    if rule.log {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rule_with_rate_limit() -> TestResult {
    let rule = Rule {
        id: 2,
        name: String::from("Rate Limited"),
        enabled: true,
        priority: 50,
        action: Action::RateLimit,
        direction: Direction::Inbound,
        protocol: Protocol::Any,
        src_ip: IpMatch::Any,
        dst_ip: IpMatch::Any,
        src_port: PortMatch::Any,
        dst_port: PortMatch::Any,
        rate_limit: Some(RateLimit { packets_per_second: 100, burst_size: 20 }),
        log: true,
        stats: RuleStats::default(),
    };
    if rule.rate_limit.is_none() {
        return TestResult::Fail;
    }
    let rl = rule.rate_limit.unwrap();
    if rl.packets_per_second != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rule_clone() -> TestResult {
    let rule = Rule {
        id: 3,
        name: String::from("Block All"),
        enabled: false,
        priority: 0,
        action: Action::Drop,
        direction: Direction::Both,
        protocol: Protocol::Any,
        src_ip: IpMatch::Any,
        dst_ip: IpMatch::Any,
        src_port: PortMatch::Any,
        dst_port: PortMatch::Any,
        rate_limit: None,
        log: true,
        stats: RuleStats::default(),
    };
    let cloned = rule.clone();
    if rule.id != cloned.id {
        return TestResult::Fail;
    }
    if rule.name != cloned.name {
        return TestResult::Fail;
    }
    if rule.enabled != cloned.enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_conn_state_new() -> TestResult {
    let state = ConnState::New;
    if state != ConnState::New {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_conn_state_established() -> TestResult {
    let state = ConnState::Established;
    if state != ConnState::Established {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_conn_state_related() -> TestResult {
    let state = ConnState::Related;
    if state != ConnState::Related {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_conn_state_invalid() -> TestResult {
    let state = ConnState::Invalid;
    if state != ConnState::Invalid {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_conn_state_time_wait() -> TestResult {
    let state = ConnState::TimeWait;
    if state != ConnState::TimeWait {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_conn_state_equality() -> TestResult {
    if ConnState::Established != ConnState::Established {
        return TestResult::Fail;
    }
    if ConnState::New == ConnState::Established {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_conn_state_clone() -> TestResult {
    let state = ConnState::Related;
    let cloned = state.clone();
    if state != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_conn_track_fields() -> TestResult {
    let conn = ConnTrack {
        src_ip: [192, 168, 1, 100],
        dst_ip: [93, 184, 216, 34],
        src_port: 54321,
        dst_port: 80,
        protocol: Protocol::Tcp,
        state: ConnState::Established,
        packets_in: 100,
        packets_out: 150,
        bytes_in: 5000,
        bytes_out: 15000,
        created_ms: 1000,
        last_seen_ms: 2000,
        timeout_ms: 300000,
    };
    if conn.src_ip != [192, 168, 1, 100] {
        return TestResult::Fail;
    }
    if conn.dst_ip != [93, 184, 216, 34] {
        return TestResult::Fail;
    }
    if conn.src_port != 54321 {
        return TestResult::Fail;
    }
    if conn.dst_port != 80 {
        return TestResult::Fail;
    }
    if conn.protocol != Protocol::Tcp {
        return TestResult::Fail;
    }
    if conn.state != ConnState::Established {
        return TestResult::Fail;
    }
    if conn.packets_in != 100 {
        return TestResult::Fail;
    }
    if conn.packets_out != 150 {
        return TestResult::Fail;
    }
    if conn.bytes_in != 5000 {
        return TestResult::Fail;
    }
    if conn.bytes_out != 15000 {
        return TestResult::Fail;
    }
    if conn.created_ms != 1000 {
        return TestResult::Fail;
    }
    if conn.last_seen_ms != 2000 {
        return TestResult::Fail;
    }
    if conn.timeout_ms != 300000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_conn_track_clone() -> TestResult {
    let conn = ConnTrack {
        src_ip: [10, 0, 0, 1],
        dst_ip: [10, 0, 0, 2],
        src_port: 1234,
        dst_port: 5678,
        protocol: Protocol::Udp,
        state: ConnState::New,
        packets_in: 1,
        packets_out: 1,
        bytes_in: 100,
        bytes_out: 100,
        created_ms: 500,
        last_seen_ms: 500,
        timeout_ms: 60000,
    };
    let cloned = conn.clone();
    if conn.src_ip != cloned.src_ip {
        return TestResult::Fail;
    }
    if conn.dst_ip != cloned.dst_ip {
        return TestResult::Fail;
    }
    if conn.state != cloned.state {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_firewall_stats_default() -> TestResult {
    let stats = FirewallStats::default();
    if stats.packets_allowed.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if stats.packets_denied.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if stats.packets_dropped.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if stats.packets_logged.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if stats.packets_rate_limited.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if stats.connections_tracked.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if stats.connections_expired.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_ip() -> TestResult {
    let ip = [192, 168, 1, 1];
    let formatted = format_ip(ip);
    if formatted != "192.168.1.1" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_ip_zeros() -> TestResult {
    let ip = [0, 0, 0, 0];
    let formatted = format_ip(ip);
    if formatted != "0.0.0.0" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_ip_max() -> TestResult {
    let ip = [255, 255, 255, 255];
    let formatted = format_ip(ip);
    if formatted != "255.255.255.255" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_ip_localhost() -> TestResult {
    let ip = [127, 0, 0, 1];
    let formatted = format_ip(ip);
    if formatted != "127.0.0.1" {
        return TestResult::Fail;
    }
    TestResult::Pass
}
