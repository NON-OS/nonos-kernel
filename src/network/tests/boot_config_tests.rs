// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::network::boot_config::types::{
    PrivacyMode, DnsMode, Ipv4Config, OnionConfig, FirewallConfig, NetworkBootConfig,
};
use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;

#[test]
fn test_privacy_mode_standard() {
    assert_eq!(PrivacyMode::Standard as u8, 0);
}

#[test]
fn test_privacy_mode_tor_only() {
    assert_eq!(PrivacyMode::TorOnly as u8, 1);
}

#[test]
fn test_privacy_mode_maximum() {
    assert_eq!(PrivacyMode::Maximum as u8, 2);
}

#[test]
fn test_privacy_mode_isolated() {
    assert_eq!(PrivacyMode::Isolated as u8, 3);
}

#[test]
fn test_privacy_mode_from_u8_standard() {
    let mode: PrivacyMode = 0u8.into();
    assert_eq!(mode, PrivacyMode::Standard);
}

#[test]
fn test_privacy_mode_from_u8_tor_only() {
    let mode: PrivacyMode = 1u8.into();
    assert_eq!(mode, PrivacyMode::TorOnly);
}

#[test]
fn test_privacy_mode_from_u8_maximum() {
    let mode: PrivacyMode = 2u8.into();
    assert_eq!(mode, PrivacyMode::Maximum);
}

#[test]
fn test_privacy_mode_from_u8_isolated() {
    let mode: PrivacyMode = 3u8.into();
    assert_eq!(mode, PrivacyMode::Isolated);
}

#[test]
fn test_privacy_mode_from_u8_invalid() {
    let mode: PrivacyMode = 255u8.into();
    assert_eq!(mode, PrivacyMode::Standard);
}

#[test]
fn test_privacy_mode_clone() {
    let mode = PrivacyMode::Maximum;
    let cloned = mode.clone();
    assert_eq!(mode, cloned);
}

#[test]
fn test_privacy_mode_copy() {
    let mode1 = PrivacyMode::TorOnly;
    let mode2 = mode1;
    assert_eq!(mode1, mode2);
}

#[test]
fn test_privacy_mode_equality() {
    assert_eq!(PrivacyMode::Standard, PrivacyMode::Standard);
    assert_ne!(PrivacyMode::Standard, PrivacyMode::Isolated);
}

#[test]
fn test_privacy_mode_debug() {
    let mode = PrivacyMode::Maximum;
    let debug_str = alloc::format!("{:?}", mode);
    assert!(debug_str.contains("Maximum"));
}

#[test]
fn test_dns_mode_dhcp() {
    let mode = DnsMode::Dhcp;
    if let DnsMode::Dhcp = mode {
        assert!(true);
    } else {
        panic!("Expected Dhcp");
    }
}

#[test]
fn test_dns_mode_custom() {
    let mode = DnsMode::Custom([8, 8, 8, 8]);
    if let DnsMode::Custom(addr) = mode {
        assert_eq!(addr, [8, 8, 8, 8]);
    } else {
        panic!("Expected Custom");
    }
}

#[test]
fn test_dns_mode_tor_dns() {
    let mode = DnsMode::TorDns;
    if let DnsMode::TorDns = mode {
        assert!(true);
    } else {
        panic!("Expected TorDns");
    }
}

#[test]
fn test_dns_mode_doh() {
    let mode = DnsMode::DoH;
    if let DnsMode::DoH = mode {
        assert!(true);
    } else {
        panic!("Expected DoH");
    }
}

#[test]
fn test_dns_mode_none() {
    let mode = DnsMode::None;
    if let DnsMode::None = mode {
        assert!(true);
    } else {
        panic!("Expected None");
    }
}

#[test]
fn test_dns_mode_clone() {
    let mode = DnsMode::Custom([1, 1, 1, 1]);
    let cloned = mode.clone();
    assert_eq!(mode, cloned);
}

#[test]
fn test_dns_mode_copy() {
    let mode1 = DnsMode::DoH;
    let mode2 = mode1;
    assert_eq!(mode1, mode2);
}

#[test]
fn test_dns_mode_equality() {
    assert_eq!(DnsMode::Dhcp, DnsMode::Dhcp);
    assert_eq!(DnsMode::Custom([8, 8, 8, 8]), DnsMode::Custom([8, 8, 8, 8]));
    assert_ne!(DnsMode::Custom([8, 8, 8, 8]), DnsMode::Custom([1, 1, 1, 1]));
    assert_ne!(DnsMode::Dhcp, DnsMode::TorDns);
}

#[test]
fn test_dns_mode_debug() {
    let mode = DnsMode::TorDns;
    let debug_str = alloc::format!("{:?}", mode);
    assert!(debug_str.contains("TorDns"));
}

#[test]
fn test_ipv4_config_default() {
    let config = Ipv4Config::default();
    assert_eq!(config.address, [0, 0, 0, 0]);
    assert_eq!(config.prefix, 24);
    assert!(config.gateway.is_none());
    assert!(config.use_dhcp);
}

#[test]
fn test_ipv4_config_fields() {
    let config = Ipv4Config {
        address: [192, 168, 1, 100],
        prefix: 24,
        gateway: Some([192, 168, 1, 1]),
        use_dhcp: false,
    };
    assert_eq!(config.address, [192, 168, 1, 100]);
    assert_eq!(config.prefix, 24);
    assert_eq!(config.gateway, Some([192, 168, 1, 1]));
    assert!(!config.use_dhcp);
}

#[test]
fn test_ipv4_config_clone() {
    let config = Ipv4Config {
        address: [10, 0, 0, 1],
        prefix: 8,
        gateway: Some([10, 0, 0, 254]),
        use_dhcp: false,
    };
    let cloned = config.clone();
    assert_eq!(config.address, cloned.address);
    assert_eq!(config.prefix, cloned.prefix);
    assert_eq!(config.gateway, cloned.gateway);
    assert_eq!(config.use_dhcp, cloned.use_dhcp);
}

#[test]
fn test_ipv4_config_no_gateway() {
    let config = Ipv4Config {
        address: [172, 16, 0, 1],
        prefix: 16,
        gateway: None,
        use_dhcp: true,
    };
    assert!(config.gateway.is_none());
}

#[test]
fn test_onion_config_default() {
    let config = OnionConfig::default();
    assert!(config.enabled);
    assert!(config.auto_connect);
    assert_eq!(config.prebuild_circuits, 3);
    assert!(!config.relay_mode);
    assert!(!config.exit_relay);
    assert!(!config.bridge_mode);
    assert!(config.bridges.is_empty());
    assert!(config.strict_exit);
    assert!(!config.block_hidden_services);
}

#[test]
fn test_onion_config_fields() {
    let config = OnionConfig {
        enabled: true,
        auto_connect: false,
        prebuild_circuits: 5,
        relay_mode: true,
        exit_relay: true,
        bridge_mode: true,
        bridges: vec![String::from("bridge1"), String::from("bridge2")],
        strict_exit: false,
        block_hidden_services: true,
    };
    assert!(config.enabled);
    assert!(!config.auto_connect);
    assert_eq!(config.prebuild_circuits, 5);
    assert!(config.relay_mode);
    assert!(config.exit_relay);
    assert!(config.bridge_mode);
    assert_eq!(config.bridges.len(), 2);
    assert!(!config.strict_exit);
    assert!(config.block_hidden_services);
}

#[test]
fn test_onion_config_clone() {
    let config = OnionConfig {
        enabled: true,
        auto_connect: true,
        prebuild_circuits: 7,
        relay_mode: false,
        exit_relay: false,
        bridge_mode: false,
        bridges: vec![String::from("test_bridge")],
        strict_exit: true,
        block_hidden_services: false,
    };
    let cloned = config.clone();
    assert_eq!(config.enabled, cloned.enabled);
    assert_eq!(config.prebuild_circuits, cloned.prebuild_circuits);
    assert_eq!(config.bridges, cloned.bridges);
}

#[test]
fn test_firewall_config_default() {
    let config = FirewallConfig::default();
    assert!(config.block_inbound);
    assert!(config.allow_outbound);
    assert!(config.allowed_ports.is_empty());
    assert!(config.blocked_ranges.is_empty());
    assert!(config.log_connections);
    assert_eq!(config.rate_limit, 1000);
}

#[test]
fn test_firewall_config_fields() {
    let config = FirewallConfig {
        block_inbound: false,
        allow_outbound: false,
        allowed_ports: vec![22, 80, 443],
        blocked_ranges: vec![([192, 168, 0, 0], 16)],
        log_connections: false,
        rate_limit: 500,
    };
    assert!(!config.block_inbound);
    assert!(!config.allow_outbound);
    assert_eq!(config.allowed_ports.len(), 3);
    assert_eq!(config.blocked_ranges.len(), 1);
    assert!(!config.log_connections);
    assert_eq!(config.rate_limit, 500);
}

#[test]
fn test_firewall_config_clone() {
    let config = FirewallConfig {
        block_inbound: true,
        allow_outbound: true,
        allowed_ports: vec![443, 8080],
        blocked_ranges: Vec::new(),
        log_connections: true,
        rate_limit: 100,
    };
    let cloned = config.clone();
    assert_eq!(config.allowed_ports, cloned.allowed_ports);
    assert_eq!(config.rate_limit, cloned.rate_limit);
}

#[test]
fn test_firewall_config_blocked_range() {
    let config = FirewallConfig {
        block_inbound: true,
        allow_outbound: true,
        allowed_ports: Vec::new(),
        blocked_ranges: vec![
            ([10, 0, 0, 0], 8),
            ([172, 16, 0, 0], 12),
            ([192, 168, 0, 0], 16),
        ],
        log_connections: false,
        rate_limit: 0,
    };
    assert_eq!(config.blocked_ranges.len(), 3);
    assert_eq!(config.blocked_ranges[0], ([10, 0, 0, 0], 8));
}

#[test]
fn test_network_boot_config_default() {
    let config = NetworkBootConfig::default();
    assert_eq!(config.privacy_mode, PrivacyMode::Standard);
    assert!(config.ipv4.use_dhcp);
    assert_eq!(config.dns_mode, DnsMode::Dhcp);
    assert!(config.dns_servers.is_empty());
    assert!(!config.onion.enabled);
    assert!(config.firewall.block_inbound);
    assert!(!config.randomize_mac);
    assert!(config.hostname.is_empty());
    assert_eq!(config.interface, "eth0");
    assert_eq!(config.boot_time, 0);
}

#[test]
fn test_network_boot_config_fields() {
    let config = NetworkBootConfig {
        privacy_mode: PrivacyMode::Maximum,
        ipv4: Ipv4Config {
            address: [10, 0, 0, 5],
            prefix: 24,
            gateway: Some([10, 0, 0, 1]),
            use_dhcp: false,
        },
        dns_mode: DnsMode::DoH,
        dns_servers: vec![[1, 1, 1, 1], [8, 8, 8, 8]],
        onion: OnionConfig::default(),
        firewall: FirewallConfig::default(),
        randomize_mac: true,
        hostname: String::from("myhost"),
        interface: String::from("wlan0"),
        boot_time: 1234567890,
    };
    assert_eq!(config.privacy_mode, PrivacyMode::Maximum);
    assert_eq!(config.ipv4.address, [10, 0, 0, 5]);
    assert_eq!(config.dns_mode, DnsMode::DoH);
    assert_eq!(config.dns_servers.len(), 2);
    assert!(config.randomize_mac);
    assert_eq!(config.hostname, "myhost");
    assert_eq!(config.interface, "wlan0");
    assert_eq!(config.boot_time, 1234567890);
}

#[test]
fn test_network_boot_config_clone() {
    let config = NetworkBootConfig {
        privacy_mode: PrivacyMode::TorOnly,
        ipv4: Ipv4Config::default(),
        dns_mode: DnsMode::TorDns,
        dns_servers: vec![[127, 0, 0, 1]],
        onion: OnionConfig {
            enabled: true,
            ..OnionConfig::default()
        },
        firewall: FirewallConfig::default(),
        randomize_mac: true,
        hostname: String::from("tor-host"),
        interface: String::from("eth0"),
        boot_time: 100,
    };
    let cloned = config.clone();
    assert_eq!(config.privacy_mode, cloned.privacy_mode);
    assert_eq!(config.dns_mode, cloned.dns_mode);
    assert_eq!(config.hostname, cloned.hostname);
}

#[test]
fn test_network_boot_config_isolated() {
    let config = NetworkBootConfig {
        privacy_mode: PrivacyMode::Isolated,
        ipv4: Ipv4Config {
            use_dhcp: false,
            address: [0, 0, 0, 0],
            ..Ipv4Config::default()
        },
        dns_mode: DnsMode::None,
        dns_servers: Vec::new(),
        onion: OnionConfig {
            enabled: false,
            ..OnionConfig::default()
        },
        firewall: FirewallConfig {
            block_inbound: true,
            allow_outbound: false,
            ..FirewallConfig::default()
        },
        randomize_mac: true,
        hostname: String::new(),
        interface: String::new(),
        boot_time: 0,
    };
    assert_eq!(config.privacy_mode, PrivacyMode::Isolated);
    assert_eq!(config.dns_mode, DnsMode::None);
    assert!(!config.firewall.allow_outbound);
}

#[test]
fn test_network_boot_config_tor_mode() {
    let config = NetworkBootConfig {
        privacy_mode: PrivacyMode::TorOnly,
        ipv4: Ipv4Config::default(),
        dns_mode: DnsMode::TorDns,
        dns_servers: Vec::new(),
        onion: OnionConfig {
            enabled: true,
            auto_connect: true,
            prebuild_circuits: 5,
            strict_exit: true,
            ..OnionConfig::default()
        },
        firewall: FirewallConfig {
            allowed_ports: vec![443, 9001, 9030],
            ..FirewallConfig::default()
        },
        randomize_mac: true,
        hostname: String::new(),
        interface: String::from("eth0"),
        boot_time: 0,
    };
    assert_eq!(config.privacy_mode, PrivacyMode::TorOnly);
    assert!(config.onion.enabled);
    assert!(config.onion.strict_exit);
    assert_eq!(config.firewall.allowed_ports.len(), 3);
}

#[test]
fn test_privacy_mode_all_variants() {
    let modes = [
        PrivacyMode::Standard,
        PrivacyMode::TorOnly,
        PrivacyMode::Maximum,
        PrivacyMode::Isolated,
    ];
    for mode in modes {
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
    }
}

#[test]
fn test_dns_mode_all_variants() {
    let modes = [
        DnsMode::Dhcp,
        DnsMode::Custom([8, 8, 8, 8]),
        DnsMode::TorDns,
        DnsMode::DoH,
        DnsMode::None,
    ];
    for mode in modes {
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
    }
}

#[test]
fn test_ipv4_config_debug() {
    let config = Ipv4Config::default();
    let debug_str = alloc::format!("{:?}", config);
    assert!(debug_str.contains("Ipv4Config"));
}

#[test]
fn test_onion_config_debug() {
    let config = OnionConfig::default();
    let debug_str = alloc::format!("{:?}", config);
    assert!(debug_str.contains("OnionConfig"));
}

#[test]
fn test_firewall_config_debug() {
    let config = FirewallConfig::default();
    let debug_str = alloc::format!("{:?}", config);
    assert!(debug_str.contains("FirewallConfig"));
}

#[test]
fn test_network_boot_config_debug() {
    let config = NetworkBootConfig::default();
    let debug_str = alloc::format!("{:?}", config);
    assert!(debug_str.contains("NetworkBootConfig"));
}

