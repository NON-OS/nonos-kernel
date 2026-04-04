use crate::network::firewall::types::{
    Action, Protocol, Direction, IpMatch, PortMatch,
    RateLimit, RuleStats, Rule, ConnState, ConnTrack, FirewallStats,
    format_ip,
};
use alloc::string::String;
use core::sync::atomic::Ordering;

#[test]
fn test_action_allow() {
    let action = Action::Allow;
    assert_eq!(action, Action::Allow);
}

#[test]
fn test_action_deny() {
    let action = Action::Deny;
    assert_eq!(action, Action::Deny);
}

#[test]
fn test_action_drop() {
    let action = Action::Drop;
    assert_eq!(action, Action::Drop);
}

#[test]
fn test_action_log() {
    let action = Action::Log;
    assert_eq!(action, Action::Log);
}

#[test]
fn test_action_rate_limit() {
    let action = Action::RateLimit;
    assert_eq!(action, Action::RateLimit);
}

#[test]
fn test_action_equality() {
    assert_eq!(Action::Allow, Action::Allow);
    assert_ne!(Action::Allow, Action::Deny);
    assert_ne!(Action::Drop, Action::Log);
}

#[test]
fn test_action_clone() {
    let action = Action::Deny;
    let cloned = action.clone();
    assert_eq!(action, cloned);
}

#[test]
fn test_protocol_any() {
    let proto = Protocol::Any;
    assert_eq!(proto, Protocol::Any);
}

#[test]
fn test_protocol_tcp() {
    let proto = Protocol::Tcp;
    assert_eq!(proto, Protocol::Tcp);
}

#[test]
fn test_protocol_udp() {
    let proto = Protocol::Udp;
    assert_eq!(proto, Protocol::Udp);
}

#[test]
fn test_protocol_icmp() {
    let proto = Protocol::Icmp;
    assert_eq!(proto, Protocol::Icmp);
}

#[test]
fn test_protocol_equality() {
    assert_eq!(Protocol::Tcp, Protocol::Tcp);
    assert_ne!(Protocol::Tcp, Protocol::Udp);
}

#[test]
fn test_protocol_clone() {
    let proto = Protocol::Icmp;
    let cloned = proto.clone();
    assert_eq!(proto, cloned);
}

#[test]
fn test_direction_inbound() {
    let dir = Direction::Inbound;
    assert_eq!(dir, Direction::Inbound);
}

#[test]
fn test_direction_outbound() {
    let dir = Direction::Outbound;
    assert_eq!(dir, Direction::Outbound);
}

#[test]
fn test_direction_both() {
    let dir = Direction::Both;
    assert_eq!(dir, Direction::Both);
}

#[test]
fn test_direction_equality() {
    assert_eq!(Direction::Inbound, Direction::Inbound);
    assert_ne!(Direction::Inbound, Direction::Outbound);
}

#[test]
fn test_direction_clone() {
    let dir = Direction::Both;
    let cloned = dir.clone();
    assert_eq!(dir, cloned);
}

#[test]
fn test_ip_match_any() {
    let m = IpMatch::Any;
    assert_eq!(m, IpMatch::Any);
}

#[test]
fn test_ip_match_single() {
    let m = IpMatch::Single([192, 168, 1, 1]);
    if let IpMatch::Single(addr) = m {
        assert_eq!(addr, [192, 168, 1, 1]);
    } else {
        panic!("Expected Single variant");
    }
}

#[test]
fn test_ip_match_subnet() {
    let m = IpMatch::Subnet([192, 168, 0, 0], 16);
    if let IpMatch::Subnet(addr, prefix) = m {
        assert_eq!(addr, [192, 168, 0, 0]);
        assert_eq!(prefix, 16);
    } else {
        panic!("Expected Subnet variant");
    }
}

#[test]
fn test_ip_match_range() {
    let m = IpMatch::Range([10, 0, 0, 1], [10, 0, 0, 255]);
    if let IpMatch::Range(start, end) = m {
        assert_eq!(start, [10, 0, 0, 1]);
        assert_eq!(end, [10, 0, 0, 255]);
    } else {
        panic!("Expected Range variant");
    }
}

#[test]
fn test_ip_match_equality() {
    assert_eq!(IpMatch::Any, IpMatch::Any);
    assert_eq!(IpMatch::Single([1, 2, 3, 4]), IpMatch::Single([1, 2, 3, 4]));
    assert_ne!(IpMatch::Single([1, 2, 3, 4]), IpMatch::Single([1, 2, 3, 5]));
}

#[test]
fn test_ip_match_clone() {
    let m = IpMatch::Subnet([172, 16, 0, 0], 12);
    let cloned = m.clone();
    assert_eq!(m, cloned);
}

#[test]
fn test_port_match_any() {
    let m = PortMatch::Any;
    assert_eq!(m, PortMatch::Any);
}

#[test]
fn test_port_match_single() {
    let m = PortMatch::Single(80);
    if let PortMatch::Single(port) = m {
        assert_eq!(port, 80);
    } else {
        panic!("Expected Single variant");
    }
}

#[test]
fn test_port_match_range() {
    let m = PortMatch::Range(1024, 65535);
    if let PortMatch::Range(start, end) = m {
        assert_eq!(start, 1024);
        assert_eq!(end, 65535);
    } else {
        panic!("Expected Range variant");
    }
}

#[test]
fn test_port_match_list() {
    let m = PortMatch::List([80, 443, 8080, 8443, 0, 0, 0, 0], 4);
    if let PortMatch::List(ports, count) = m {
        assert_eq!(count, 4);
        assert_eq!(ports[0], 80);
        assert_eq!(ports[1], 443);
        assert_eq!(ports[2], 8080);
        assert_eq!(ports[3], 8443);
    } else {
        panic!("Expected List variant");
    }
}

#[test]
fn test_port_match_equality() {
    assert_eq!(PortMatch::Any, PortMatch::Any);
    assert_eq!(PortMatch::Single(443), PortMatch::Single(443));
    assert_ne!(PortMatch::Single(80), PortMatch::Single(443));
}

#[test]
fn test_port_match_clone() {
    let m = PortMatch::Range(1, 1023);
    let cloned = m.clone();
    assert_eq!(m, cloned);
}

#[test]
fn test_rate_limit_fields() {
    let rl = RateLimit {
        packets_per_second: 100,
        burst_size: 10,
    };
    assert_eq!(rl.packets_per_second, 100);
    assert_eq!(rl.burst_size, 10);
}

#[test]
fn test_rate_limit_clone() {
    let rl = RateLimit {
        packets_per_second: 1000,
        burst_size: 50,
    };
    let cloned = rl.clone();
    assert_eq!(rl.packets_per_second, cloned.packets_per_second);
    assert_eq!(rl.burst_size, cloned.burst_size);
}

#[test]
fn test_rule_stats_default() {
    let stats = RuleStats::default();
    assert_eq!(stats.matches.load(Ordering::Relaxed), 0);
    assert_eq!(stats.bytes.load(Ordering::Relaxed), 0);
    assert_eq!(stats.last_match_ms.load(Ordering::Relaxed), 0);
}

#[test]
fn test_rule_stats_clone() {
    let stats = RuleStats::default();
    stats.matches.store(100, Ordering::Relaxed);
    stats.bytes.store(5000, Ordering::Relaxed);
    stats.last_match_ms.store(1000, Ordering::Relaxed);

    let cloned = stats.clone();
    assert_eq!(cloned.matches.load(Ordering::Relaxed), 100);
    assert_eq!(cloned.bytes.load(Ordering::Relaxed), 5000);
    assert_eq!(cloned.last_match_ms.load(Ordering::Relaxed), 1000);
}

#[test]
fn test_rule_fields() {
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
    assert_eq!(rule.id, 1);
    assert_eq!(rule.name, "Allow HTTP");
    assert!(rule.enabled);
    assert_eq!(rule.priority, 100);
    assert_eq!(rule.action, Action::Allow);
    assert_eq!(rule.direction, Direction::Outbound);
    assert_eq!(rule.protocol, Protocol::Tcp);
    assert!(rule.rate_limit.is_none());
    assert!(!rule.log);
}

#[test]
fn test_rule_with_rate_limit() {
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
        rate_limit: Some(RateLimit {
            packets_per_second: 100,
            burst_size: 20,
        }),
        log: true,
        stats: RuleStats::default(),
    };
    assert!(rule.rate_limit.is_some());
    let rl = rule.rate_limit.unwrap();
    assert_eq!(rl.packets_per_second, 100);
}

#[test]
fn test_rule_clone() {
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
    assert_eq!(rule.id, cloned.id);
    assert_eq!(rule.name, cloned.name);
    assert_eq!(rule.enabled, cloned.enabled);
}

#[test]
fn test_conn_state_new() {
    let state = ConnState::New;
    assert_eq!(state, ConnState::New);
}

#[test]
fn test_conn_state_established() {
    let state = ConnState::Established;
    assert_eq!(state, ConnState::Established);
}

#[test]
fn test_conn_state_related() {
    let state = ConnState::Related;
    assert_eq!(state, ConnState::Related);
}

#[test]
fn test_conn_state_invalid() {
    let state = ConnState::Invalid;
    assert_eq!(state, ConnState::Invalid);
}

#[test]
fn test_conn_state_time_wait() {
    let state = ConnState::TimeWait;
    assert_eq!(state, ConnState::TimeWait);
}

#[test]
fn test_conn_state_equality() {
    assert_eq!(ConnState::Established, ConnState::Established);
    assert_ne!(ConnState::New, ConnState::Established);
}

#[test]
fn test_conn_state_clone() {
    let state = ConnState::Related;
    let cloned = state.clone();
    assert_eq!(state, cloned);
}

#[test]
fn test_conn_track_fields() {
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
    assert_eq!(conn.src_ip, [192, 168, 1, 100]);
    assert_eq!(conn.dst_ip, [93, 184, 216, 34]);
    assert_eq!(conn.src_port, 54321);
    assert_eq!(conn.dst_port, 80);
    assert_eq!(conn.protocol, Protocol::Tcp);
    assert_eq!(conn.state, ConnState::Established);
    assert_eq!(conn.packets_in, 100);
    assert_eq!(conn.packets_out, 150);
    assert_eq!(conn.bytes_in, 5000);
    assert_eq!(conn.bytes_out, 15000);
    assert_eq!(conn.created_ms, 1000);
    assert_eq!(conn.last_seen_ms, 2000);
    assert_eq!(conn.timeout_ms, 300000);
}

#[test]
fn test_conn_track_clone() {
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
    assert_eq!(conn.src_ip, cloned.src_ip);
    assert_eq!(conn.dst_ip, cloned.dst_ip);
    assert_eq!(conn.state, cloned.state);
}

#[test]
fn test_firewall_stats_default() {
    let stats = FirewallStats::default();
    assert_eq!(stats.packets_allowed.load(Ordering::Relaxed), 0);
    assert_eq!(stats.packets_denied.load(Ordering::Relaxed), 0);
    assert_eq!(stats.packets_dropped.load(Ordering::Relaxed), 0);
    assert_eq!(stats.packets_logged.load(Ordering::Relaxed), 0);
    assert_eq!(stats.packets_rate_limited.load(Ordering::Relaxed), 0);
    assert_eq!(stats.connections_tracked.load(Ordering::Relaxed), 0);
    assert_eq!(stats.connections_expired.load(Ordering::Relaxed), 0);
}

#[test]
fn test_format_ip() {
    let ip = [192, 168, 1, 1];
    let formatted = format_ip(ip);
    assert_eq!(formatted, "192.168.1.1");
}

#[test]
fn test_format_ip_zeros() {
    let ip = [0, 0, 0, 0];
    let formatted = format_ip(ip);
    assert_eq!(formatted, "0.0.0.0");
}

#[test]
fn test_format_ip_max() {
    let ip = [255, 255, 255, 255];
    let formatted = format_ip(ip);
    assert_eq!(formatted, "255.255.255.255");
}

#[test]
fn test_format_ip_localhost() {
    let ip = [127, 0, 0, 1];
    let formatted = format_ip(ip);
    assert_eq!(formatted, "127.0.0.1");
}
