// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::sys::serial;

const ENABLE_NET_XHCI: bool = false;

pub fn init_network() {
    serial::println(b"[NET] Initializing network...");
    crate::network::init_network_stack();
    serial::println(b"[NET] Network stack initialized");
    init_usb_networking();
    let (network_ready, is_qemu) = probe_ethernet_devices();
    if network_ready { configure_network(is_qemu); }
    init_wifi();
    if !network_ready && crate::drivers::wifi::init() == 0 { serial::println(b"[NET] Warning: No network interfaces available"); }
}

fn init_usb_networking() {
    if !ENABLE_NET_XHCI {
        serial::println(b"[NET] usb_eth=skipped(owner=hid)");
        return;
    }
    serial::println(b"[NET] Initializing USB...");
    match crate::drivers::xhci::init_xhci() {
        Ok(_) => {
            serial::println(b"[NET] xHCI USB controller ready");
            match crate::drivers::usb::init_usb() {
                Ok(_) => {
                    serial::println(b"[NET] USB subsystem initialized");
                    if crate::drivers::usb::rtl8152::is_connected() { serial::println(b"[NET] RTL8152 USB Ethernet detected and registered"); }
                    if crate::drivers::usb::cdc_eth::is_connected() { serial::println(b"[NET] CDC USB Ethernet detected and registered"); }
                }
                Err(e) => { serial::print(b"[NET] USB init: "); serial::println(e.as_bytes()); }
            }
        }
        Err(e) => { serial::print(b"[NET] xHCI: "); serial::println(e.as_bytes()); }
    }
}

fn probe_ethernet_devices() -> (bool, bool) {
    if crate::network::stack::is_network_available() { serial::println(b"[NET] USB Ethernet active"); return (true, false); }
    if let Ok(()) = crate::drivers::init_virtio_net() {
        serial::println(b"[NET] VirtIO-net driver initialized");
        crate::drivers::virtio_net::interface::register_with_smoltcp();
        serial::println(b"[NET] VirtIO-net registered with stack");
        return (true, true);
    }
    if let Ok(()) = crate::drivers::network::e1000::init() {
        serial::println(b"[NET] e1000 Ethernet driver initialized");
        if let Some(dev) = crate::drivers::network::e1000::get_driver() {
            crate::network::register_device(dev);
            serial::println(b"[NET] e1000 registered with stack");
            return (true, true);
        }
    }
    if crate::drivers::rtl8168_is_present() {
        serial::println(b"[NET] RTL8168 Gigabit Ethernet detected");
        crate::drivers::rtl8168::register_with_network_stack();
        serial::println(b"[NET] RTL8168 registered with stack");
        return (true, false);
    }
    if crate::drivers::rtl8139_is_present() {
        serial::println(b"[NET] RTL8139 Fast Ethernet detected");
        crate::drivers::rtl8139::register_with_network_stack();
        serial::println(b"[NET] RTL8139 registered with stack");
        return (true, false);
    }
    (false, false)
}

fn configure_network(is_qemu: bool) {
    if let Some(stack) = crate::network::get_network_stack() {
        if is_qemu {
            serial::println(b"[NET] QEMU mode: Using static IP 10.0.2.15...");
            stack.set_ipv4_config([10, 0, 2, 15], 24, Some([10, 0, 2, 2]));
            stack.set_default_dns_v4([10, 0, 2, 3]);
            crate::network::stack::set_network_connected(true);
            serial::println(b"[NET] Static IP configured");
        } else {
            serial::println(b"[NET] Real hardware: Requesting DHCP lease...");
            match stack.request_dhcp() {
                Ok(_) => { serial::println(b"[NET] DHCP lease acquired!"); crate::network::stack::set_network_connected(true); }
                Err(e) => { serial::print(b"[NET] DHCP failed: "); serial::println(e.as_bytes()); serial::println(b"[NET] Network available but not configured"); }
            }
        }
    }
    serial::println(b"[NET] Ethernet ready");
}

fn init_wifi() {
    serial::println(b"[NET] Initializing WiFi...");
    let wifi_count = crate::drivers::wifi::init();
    if wifi_count > 0 {
        serial::println(b"[NET] WiFi adapter(s) found");
        serial::println(b"[NET] Loading WiFi firmware...");
        match crate::drivers::wifi::try_load_firmware() {
            Ok(()) => serial::println(b"[NET] WiFi firmware loaded successfully"),
            Err(_) => serial::println(b"[NET] WiFi firmware not found on USB - place IWLWIFI.BIN or RTW88FW.BIN on FAT32 USB drive"),
        }
        crate::drivers::wifi::print_status();
    } else { serial::println(b"[NET] No WiFi adapter found"); }
}
