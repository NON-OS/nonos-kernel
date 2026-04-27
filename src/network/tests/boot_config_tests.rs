// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::network::boot_config::types::{
    DnsMode, FirewallConfig, Ipv4Config, NetworkBootConfig, OnionConfig, PrivacyMode,
};
use crate::test::framework::TestResult;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub(crate) fn test_privacy_mode_standard() -> TestResult {
    if PrivacyMode::Standard as u8 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_mode_tor_only() -> TestResult {
    if PrivacyMode::TorOnly as u8 != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_mode_maximum() -> TestResult {
    if PrivacyMode::Maximum as u8 != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_mode_isolated() -> TestResult {
    if PrivacyMode::Isolated as u8 != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_mode_from_u8_standard() -> TestResult {
    let mode: PrivacyMode = 0u8.into();
    if mode != PrivacyMode::Standard {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_mode_from_u8_tor_only() -> TestResult {
    let mode: PrivacyMode = 1u8.into();
    if mode != PrivacyMode::TorOnly {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_mode_from_u8_maximum() -> TestResult {
    let mode: PrivacyMode = 2u8.into();
    if mode != PrivacyMode::Maximum {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_mode_from_u8_isolated() -> TestResult {
    let mode: PrivacyMode = 3u8.into();
    if mode != PrivacyMode::Isolated {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_mode_from_u8_invalid() -> TestResult {
    let mode: PrivacyMode = 255u8.into();
    if mode != PrivacyMode::Standard {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_mode_clone() -> TestResult {
    let mode = PrivacyMode::Maximum;
    let cloned = mode.clone();
    if mode != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_mode_copy() -> TestResult {
    let mode1 = PrivacyMode::TorOnly;
    let mode2 = mode1;
    if mode1 != mode2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_mode_equality() -> TestResult {
    if PrivacyMode::Standard != PrivacyMode::Standard {
        return TestResult::Fail;
    }
    if PrivacyMode::Standard == PrivacyMode::Isolated {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_mode_debug() -> TestResult {
    let mode = PrivacyMode::Maximum;
    let debug_str = alloc::format!("{:?}", mode);
    if !debug_str.contains("Maximum") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_mode_dhcp() -> TestResult {
    let mode = DnsMode::Dhcp;
    if let DnsMode::Dhcp = mode {
        // ok
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_mode_custom() -> TestResult {
    let mode = DnsMode::Custom([8, 8, 8, 8]);
    if let DnsMode::Custom(addr) = mode {
        if addr != [8, 8, 8, 8] {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_mode_tor_dns() -> TestResult {
    let mode = DnsMode::TorDns;
    if let DnsMode::TorDns = mode {
        // ok
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_mode_doh() -> TestResult {
    let mode = DnsMode::DoH;
    if let DnsMode::DoH = mode {
        // ok
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_mode_none() -> TestResult {
    let mode = DnsMode::None;
    if let DnsMode::None = mode {
        // ok
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_mode_clone() -> TestResult {
    let mode = DnsMode::Custom([1, 1, 1, 1]);
    let cloned = mode.clone();
    if mode != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_mode_copy() -> TestResult {
    let mode1 = DnsMode::DoH;
    let mode2 = mode1;
    if mode1 != mode2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_mode_equality() -> TestResult {
    if DnsMode::Dhcp != DnsMode::Dhcp {
        return TestResult::Fail;
    }
    if DnsMode::Custom([8, 8, 8, 8]) != DnsMode::Custom([8, 8, 8, 8]) {
        return TestResult::Fail;
    }
    if DnsMode::Custom([8, 8, 8, 8]) == DnsMode::Custom([1, 1, 1, 1]) {
        return TestResult::Fail;
    }
    if DnsMode::Dhcp == DnsMode::TorDns {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_mode_debug() -> TestResult {
    let mode = DnsMode::TorDns;
    let debug_str = alloc::format!("{:?}", mode);
    if !debug_str.contains("TorDns") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipv4_config_default() -> TestResult {
    let config = Ipv4Config::default();
    if config.address != [0, 0, 0, 0] {
        return TestResult::Fail;
    }
    if config.prefix != 24 {
        return TestResult::Fail;
    }
    if !config.gateway.is_none() {
        return TestResult::Fail;
    }
    if !config.use_dhcp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipv4_config_fields() -> TestResult {
    let config = Ipv4Config {
        address: [192, 168, 1, 100],
        prefix: 24,
        gateway: Some([192, 168, 1, 1]),
        use_dhcp: false,
    };
    if config.address != [192, 168, 1, 100] {
        return TestResult::Fail;
    }
    if config.prefix != 24 {
        return TestResult::Fail;
    }
    if config.gateway != Some([192, 168, 1, 1]) {
        return TestResult::Fail;
    }
    if config.use_dhcp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipv4_config_clone() -> TestResult {
    let config = Ipv4Config {
        address: [10, 0, 0, 1],
        prefix: 8,
        gateway: Some([10, 0, 0, 254]),
        use_dhcp: false,
    };
    let cloned = config.clone();
    if config.address != cloned.address {
        return TestResult::Fail;
    }
    if config.prefix != cloned.prefix {
        return TestResult::Fail;
    }
    if config.gateway != cloned.gateway {
        return TestResult::Fail;
    }
    if config.use_dhcp != cloned.use_dhcp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipv4_config_no_gateway() -> TestResult {
    let config = Ipv4Config { address: [172, 16, 0, 1], prefix: 16, gateway: None, use_dhcp: true };
    if !config.gateway.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_onion_config_default() -> TestResult {
    let config = OnionConfig::default();
    if !config.enabled {
        return TestResult::Fail;
    }
    if !config.auto_connect {
        return TestResult::Fail;
    }
    if config.prebuild_circuits != 3 {
        return TestResult::Fail;
    }
    if config.relay_mode {
        return TestResult::Fail;
    }
    if config.exit_relay {
        return TestResult::Fail;
    }
    if config.bridge_mode {
        return TestResult::Fail;
    }
    if !config.bridges.is_empty() {
        return TestResult::Fail;
    }
    if !config.strict_exit {
        return TestResult::Fail;
    }
    if config.block_hidden_services {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_onion_config_fields() -> TestResult {
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
    if !config.enabled {
        return TestResult::Fail;
    }
    if config.auto_connect {
        return TestResult::Fail;
    }
    if config.prebuild_circuits != 5 {
        return TestResult::Fail;
    }
    if !config.relay_mode {
        return TestResult::Fail;
    }
    if !config.exit_relay {
        return TestResult::Fail;
    }
    if !config.bridge_mode {
        return TestResult::Fail;
    }
    if config.bridges.len() != 2 {
        return TestResult::Fail;
    }
    if config.strict_exit {
        return TestResult::Fail;
    }
    if !config.block_hidden_services {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_onion_config_clone() -> TestResult {
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
    if config.enabled != cloned.enabled {
        return TestResult::Fail;
    }
    if config.prebuild_circuits != cloned.prebuild_circuits {
        return TestResult::Fail;
    }
    if config.bridges != cloned.bridges {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_firewall_config_default() -> TestResult {
    let config = FirewallConfig::default();
    if !config.block_inbound {
        return TestResult::Fail;
    }
    if !config.allow_outbound {
        return TestResult::Fail;
    }
    if !config.allowed_ports.is_empty() {
        return TestResult::Fail;
    }
    if !config.blocked_ranges.is_empty() {
        return TestResult::Fail;
    }
    if !config.log_connections {
        return TestResult::Fail;
    }
    if config.rate_limit != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_firewall_config_fields() -> TestResult {
    let config = FirewallConfig {
        block_inbound: false,
        allow_outbound: false,
        allowed_ports: vec![22, 80, 443],
        blocked_ranges: vec![([192, 168, 0, 0], 16)],
        log_connections: false,
        rate_limit: 500,
    };
    if config.block_inbound {
        return TestResult::Fail;
    }
    if config.allow_outbound {
        return TestResult::Fail;
    }
    if config.allowed_ports.len() != 3 {
        return TestResult::Fail;
    }
    if config.blocked_ranges.len() != 1 {
        return TestResult::Fail;
    }
    if config.log_connections {
        return TestResult::Fail;
    }
    if config.rate_limit != 500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_firewall_config_clone() -> TestResult {
    let config = FirewallConfig {
        block_inbound: true,
        allow_outbound: true,
        allowed_ports: vec![443, 8080],
        blocked_ranges: Vec::new(),
        log_connections: true,
        rate_limit: 100,
    };
    let cloned = config.clone();
    if config.allowed_ports != cloned.allowed_ports {
        return TestResult::Fail;
    }
    if config.rate_limit != cloned.rate_limit {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_firewall_config_blocked_range() -> TestResult {
    let config = FirewallConfig {
        block_inbound: true,
        allow_outbound: true,
        allowed_ports: Vec::new(),
        blocked_ranges: vec![([10, 0, 0, 0], 8), ([172, 16, 0, 0], 12), ([192, 168, 0, 0], 16)],
        log_connections: false,
        rate_limit: 0,
    };
    if config.blocked_ranges.len() != 3 {
        return TestResult::Fail;
    }
    if config.blocked_ranges[0] != ([10, 0, 0, 0], 8) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_boot_config_default() -> TestResult {
    let config = NetworkBootConfig::default();
    if config.privacy_mode != PrivacyMode::Standard {
        return TestResult::Fail;
    }
    if !config.ipv4.use_dhcp {
        return TestResult::Fail;
    }
    if config.dns_mode != DnsMode::Dhcp {
        return TestResult::Fail;
    }
    if !config.dns_servers.is_empty() {
        return TestResult::Fail;
    }
    if config.onion.enabled {
        return TestResult::Fail;
    }
    if !config.firewall.block_inbound {
        return TestResult::Fail;
    }
    if config.randomize_mac {
        return TestResult::Fail;
    }
    if !config.hostname.is_empty() {
        return TestResult::Fail;
    }
    if config.interface != "eth0" {
        return TestResult::Fail;
    }
    if config.boot_time != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_boot_config_fields() -> TestResult {
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
    if config.privacy_mode != PrivacyMode::Maximum {
        return TestResult::Fail;
    }
    if config.ipv4.address != [10, 0, 0, 5] {
        return TestResult::Fail;
    }
    if config.dns_mode != DnsMode::DoH {
        return TestResult::Fail;
    }
    if config.dns_servers.len() != 2 {
        return TestResult::Fail;
    }
    if !config.randomize_mac {
        return TestResult::Fail;
    }
    if config.hostname != "myhost" {
        return TestResult::Fail;
    }
    if config.interface != "wlan0" {
        return TestResult::Fail;
    }
    if config.boot_time != 1234567890 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_boot_config_clone() -> TestResult {
    let config = NetworkBootConfig {
        privacy_mode: PrivacyMode::TorOnly,
        ipv4: Ipv4Config::default(),
        dns_mode: DnsMode::TorDns,
        dns_servers: vec![[127, 0, 0, 1]],
        onion: OnionConfig { enabled: true, ..OnionConfig::default() },
        firewall: FirewallConfig::default(),
        randomize_mac: true,
        hostname: String::from("tor-host"),
        interface: String::from("eth0"),
        boot_time: 100,
    };
    let cloned = config.clone();
    if config.privacy_mode != cloned.privacy_mode {
        return TestResult::Fail;
    }
    if config.dns_mode != cloned.dns_mode {
        return TestResult::Fail;
    }
    if config.hostname != cloned.hostname {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_boot_config_isolated() -> TestResult {
    let config = NetworkBootConfig {
        privacy_mode: PrivacyMode::Isolated,
        ipv4: Ipv4Config { use_dhcp: false, address: [0, 0, 0, 0], ..Ipv4Config::default() },
        dns_mode: DnsMode::None,
        dns_servers: Vec::new(),
        onion: OnionConfig { enabled: false, ..OnionConfig::default() },
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
    if config.privacy_mode != PrivacyMode::Isolated {
        return TestResult::Fail;
    }
    if config.dns_mode != DnsMode::None {
        return TestResult::Fail;
    }
    if config.firewall.allow_outbound {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_boot_config_tor_mode() -> TestResult {
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
    if config.privacy_mode != PrivacyMode::TorOnly {
        return TestResult::Fail;
    }
    if !config.onion.enabled {
        return TestResult::Fail;
    }
    if !config.onion.strict_exit {
        return TestResult::Fail;
    }
    if config.firewall.allowed_ports.len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_mode_all_variants() -> TestResult {
    let modes =
        [PrivacyMode::Standard, PrivacyMode::TorOnly, PrivacyMode::Maximum, PrivacyMode::Isolated];
    for mode in modes {
        let cloned = mode.clone();
        if mode != cloned {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_dns_mode_all_variants() -> TestResult {
    let modes = [
        DnsMode::Dhcp,
        DnsMode::Custom([8, 8, 8, 8]),
        DnsMode::TorDns,
        DnsMode::DoH,
        DnsMode::None,
    ];
    for mode in modes {
        let cloned = mode.clone();
        if mode != cloned {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_ipv4_config_debug() -> TestResult {
    let config = Ipv4Config::default();
    let debug_str = alloc::format!("{:?}", config);
    if !debug_str.contains("Ipv4Config") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_onion_config_debug() -> TestResult {
    let config = OnionConfig::default();
    let debug_str = alloc::format!("{:?}", config);
    if !debug_str.contains("OnionConfig") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_firewall_config_debug() -> TestResult {
    let config = FirewallConfig::default();
    let debug_str = alloc::format!("{:?}", config);
    if !debug_str.contains("FirewallConfig") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_boot_config_debug() -> TestResult {
    let config = NetworkBootConfig::default();
    let debug_str = alloc::format!("{:?}", config);
    if !debug_str.contains("NetworkBootConfig") {
        return TestResult::Fail;
    }
    TestResult::Pass
}
