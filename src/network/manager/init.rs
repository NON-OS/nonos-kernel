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


use crate::network::boot_config::{self, PrivacyMode};
use crate::network::stack::{init_network_stack, get_network_stack};
use crate::network::onion;

pub fn init() {
    crate::log::info!("net: initializing NONOS network subsystem");

    boot_config::init();
    boot_config::preset_standard();
    boot_config::init_from_handoff();
    init_network_stack();

    if let Some(config) = boot_config::get_config() {
        if config.privacy_mode == PrivacyMode::Isolated {
            crate::log::info!("net: ISOLATED mode - skipping network init");
            boot_config::lock_config();
            return;
        }

        if config.ipv4.use_dhcp {
            if let Some(stack) = get_network_stack() {
                let mut dhcp_success = false;
                for attempt in 0..3 {
                    match stack.request_dhcp() {
                        Ok(lease) => {
                            crate::log::info!(
                                "net: DHCP acquired IP {}.{}.{}.{}, gw {}.{}.{}.{}",
                                lease.ip[0], lease.ip[1], lease.ip[2], lease.ip[3],
                                lease.gateway[0], lease.gateway[1], lease.gateway[2], lease.gateway[3]
                            );
                            dhcp_success = true;
                            break;
                        }
                        Err(_) => {
                            if attempt < 2 {
                                crate::log::info!("net: DHCP attempt {} failed, retrying...", attempt + 1);
                                for _ in 0..100_000 { core::hint::spin_loop(); }
                            }
                        }
                    }
                }

                if !dhcp_success {
                    let mac = stack.get_mac_address();
                    let octet3 = mac[4];
                    let octet4 = if mac[5] == 0 { 1 } else { mac[5] };

                    crate::log::warn!(
                        "net: DHCP failed after 3 attempts, using link-local 169.254.{}.{}",
                        octet3, octet4
                    );
                    stack.set_ipv4_config([169, 254, octet3, octet4], 16, None);
                    stack.set_default_dns_v4([1, 1, 1, 1]);
                }
            }
        } else if let Some(stack) = get_network_stack() {
            stack.set_ipv4_config(config.ipv4.address, config.ipv4.prefix, config.ipv4.gateway);
        }
    }

    if let Err(e) = onion::tls::init_tls_stack_production(&onion::tls::KERNEL_TLS_CRYPTO) {
        crate::log::error!("tls: init failed: {:?}", e);
    } else {
        crate::log::info!("tls: production crypto/verifier initialized");
    }

    if let Err(e) = boot_config::apply_boot_config() {
        crate::log::error!("net: boot config apply failed: {}", e);
    }

    crate::log::info!("net: network subsystem initialized");
    boot_config::print_status();
}

pub fn init_with_preset(preset: PrivacyMode) {
    boot_config::init();

    match preset {
        PrivacyMode::Standard => boot_config::preset_standard(),
        PrivacyMode::TorOnly => boot_config::preset_anonymous(),
        PrivacyMode::Maximum => boot_config::preset_maximum(),
        PrivacyMode::Isolated => boot_config::preset_isolated(),
    }

    init_network_stack();

    if let Some(config) = boot_config::get_config() {
        if config.privacy_mode == PrivacyMode::Isolated {
            crate::log::info!("net: ISOLATED mode - network disabled");
            boot_config::lock_config();
            return;
        }
    }

    if let Err(e) = boot_config::apply_boot_config() {
        crate::log::error!("net: boot config apply failed: {}", e);
    }
}

pub fn configure_ipv4(ip: [u8; 4], prefix: u8, gateway: Option<[u8; 4]>, dns_v4: Option<[u8; 4]>) {
    if let Some(stack) = get_network_stack() {
        stack.set_ipv4_config(ip, prefix, gateway);
        if let Some(dns) = dns_v4 {
            stack.set_default_dns_v4(dns);
        }
        crate::log::info!(
            "net: configured IPv4 {:?}/{}, gw={:?}, dns={:?}",
            ip, prefix, gateway, dns_v4
        );
    } else {
        crate::log_warn!("net: stack not initialized (configure_ipv4 ignored)");
    }
}
