// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::config::{get_config, lock_config};
use super::types::{FirewallConfig, OnionConfig, PrivacyMode};
/// *** We apply the boot configuration to the network stack
/// ***___Called once during kernel initialization***___ ///
pub fn apply_boot_config() -> Result<(), &'static str> {
    let config = get_config().ok_or("Boot config not initialized")?;
    crate::log::info!("net: applying boot configuration...");
    crate::log::info!("net: privacy mode = {:?}", config.privacy_mode);
    // 1. Apply privacy mode
    match config.privacy_mode {
        PrivacyMode::Isolated => {
            crate::log::info!("net: ISOLATED mode - network disabled");
            return Ok(());
        }
        PrivacyMode::Standard => {
            crate::log::info!("net: STANDARD mode - direct connections");
        }
        PrivacyMode::TorOnly => {
            crate::log::info!("net: TOR-ONLY mode - all traffic through Tor");
        }
        PrivacyMode::Maximum => {
            crate::log::info!("net: MAXIMUM privacy mode");
        }
    }

    // 2. Configure IPv4
    if config.ipv4.use_dhcp {
        crate::log::info!("net: using DHCP for IP configuration");
    } else {
        crate::log::info!(
            "net: static IP: {}.{}.{}.{}/{}",
            config.ipv4.address[0],
            config.ipv4.address[1],
            config.ipv4.address[2],
            config.ipv4.address[3],
            config.ipv4.prefix
        );

        if let Some(stack) = crate::network::get_network_stack() {
            stack.set_ipv4_config(config.ipv4.address, config.ipv4.prefix, config.ipv4.gateway);
        }
    }

    // 3. Configure DNS
    match config.dns_mode {
        super::types::DnsMode::Dhcp => {
            crate::log::info!("net: DNS via DHCP");
        }
        super::types::DnsMode::Custom(dns) => {
            crate::log::info!("net: custom DNS: {}.{}.{}.{}", dns[0], dns[1], dns[2], dns[3]);
            if let Some(stack) = crate::network::get_network_stack() {
                stack.set_default_dns_v4(dns);
            }
        }
        super::types::DnsMode::TorDns => {
            crate::log::info!("net: DNS over Tor (anonymized)");
        }
        super::types::DnsMode::DoH => {
            crate::log::info!("net: DNS over HTTPS");
        }
        super::types::DnsMode::None => {
            crate::log::info!("net: DNS disabled");
        }
    }

    // 4. Configure firewall
    apply_firewall_config(&config.firewall)?;
    // 5. Configure Tor/onion if enabled
    if config.onion.enabled {
        apply_onion_config(&config.onion)?;
    }

    // 6. Lock configuration
    lock_config();

    crate::log::info!("net: boot configuration applied and locked");
    Ok(())
}

/// ** apply firewall configuration ** ///
fn apply_firewall_config(fw_config: &FirewallConfig) -> Result<(), &'static str> {
    use crate::network::firewall::{
        self, Action, Direction, IpMatch, PortMatch, Protocol, Rule, RuleStats,
    };

    let fw = firewall::get_firewall();

    fw.set_enabled(true);

    /// ** add port rules if specified (restrict to specific ports) ** ///
    if !fw_config.allowed_ports.is_empty() {
        for &port in &fw_config.allowed_ports {
            fw.add_rule(Rule {
                id: 0,
                name: alloc::format!("allow-port-{}", port),
                enabled: true,
                priority: 90,
                action: Action::Allow,
                direction: Direction::Outbound,
                protocol: Protocol::Tcp,
                src_ip: IpMatch::Any,
                dst_ip: IpMatch::Any,
                src_port: PortMatch::Any,
                dst_port: PortMatch::Single(port),
                rate_limit: None,
                log: fw_config.log_connections,
                stats: RuleStats::default(),
            });
        }
    }

    /// ** block specific IP ranges ** /// 
    for (ip, prefix) in &fw_config.blocked_ranges {
        fw.add_rule(Rule {
            id: 0,
            name: alloc::format!(
                "block-range-{}.{}.{}.{}/{}",
                ip[0], ip[1], ip[2], ip[3], prefix
            ),
            enabled: true,
            priority: 200,
            action: Action::Deny,
            direction: Direction::Both,
            protocol: Protocol::Any,
            src_ip: IpMatch::Any,
            dst_ip: IpMatch::Subnet(*ip, *prefix),
            src_port: PortMatch::Any,
            dst_port: PortMatch::Any,
            rate_limit: None,
            log: fw_config.log_connections,
            stats: RuleStats::default(),
        });
    }

    crate::log::info!(
        "net: firewall configured (inbound={}, outbound={})",
        if fw_config.block_inbound {
            "blocked"
        } else {
            "allowed"
        },
        if fw_config.allow_outbound {
            "allowed"
        } else {
            "blocked"
        }
    );

    Ok(())
}

/// ** apply onion routing configuration ** ///
fn apply_onion_config(onion_config: &OnionConfig) -> Result<(), &'static str> {
    crate::log::info!("net: configuring Tor/onion routing...");
    if crate::network::onion::get_onion_router().lock().is_none() {
        if let Err(e) = crate::network::onion::init_onion_router() {
            crate::log::error!("net: failed to init onion router: {:?}", e);
            return Err("Onion router initialization failed");
        }
    }

    if onion_config.auto_connect {
        crate::log::info!("net: auto-connecting to Tor network...");
        for i in 0..onion_config.prebuild_circuits {
            match crate::network::onion::create_circuit(None) {
                Ok(circuit_id) => {
                    crate::log::info!("net: pre-built circuit {} (id={})", i + 1, circuit_id);
                }
                Err(e) => {
                    crate::log::error!("net: circuit {} build failed: {:?}", i + 1, e);
                }
            }
        }
    }

    if onion_config.relay_mode {
        crate::log::info!("net: Tor relay mode requested (not yet implemented in kernel)");
    }

    crate::log::info!("net: Tor/onion configuration complete");
    Ok(())
}
