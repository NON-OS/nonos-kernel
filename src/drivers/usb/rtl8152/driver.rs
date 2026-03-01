// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::drivers::usb::{
    UsbClassDriver, UsbDevice, UsbConfiguration, UsbInterfaceInfo,
    register_class_driver, get_manager,
};
use crate::network::stack::register_device;

use super::constants::*;
use super::device::Rtl8152Device;

static RTL8152_CONNECTED: AtomicBool = AtomicBool::new(false);

pub struct Rtl8152Driver;

impl Rtl8152Driver {
    fn is_supported_device(vid: u16, pid: u16) -> bool {
        if vid == REALTEK_VENDOR_ID && RTL8152_PRODUCT_IDS.contains(&pid) {
            return true;
        }
        if vid == HAMA_VENDOR_ID && HAMA_PRODUCT_IDS.contains(&pid) {
            return true;
        }
        if vid == LENOVO_VENDOR_ID && LENOVO_PRODUCT_IDS.contains(&pid) {
            return true;
        }
        if vid == SAMSUNG_VENDOR_ID && SAMSUNG_PRODUCT_IDS.contains(&pid) {
            return true;
        }
        if vid == LINKSYS_VENDOR_ID && LINKSYS_PRODUCT_IDS.contains(&pid) {
            return true;
        }
        if vid == NVIDIA_VENDOR_ID && NVIDIA_PRODUCT_IDS.contains(&pid) {
            return true;
        }
        if vid == TPLINK_VENDOR_ID && TPLINK_PRODUCT_IDS.contains(&pid) {
            return true;
        }
        if vid == ASIX_VENDOR_ID && ASIX_PRODUCT_IDS.contains(&pid) {
            return true;
        }
        if vid == DLINK_VENDOR_ID && DLINK_PRODUCT_IDS.contains(&pid) {
            return true;
        }
        if vid == BELKIN_VENDOR_ID && BELKIN_PRODUCT_IDS.contains(&pid) {
            return true;
        }
        if vid == APPLE_VENDOR_ID && APPLE_PRODUCT_IDS.contains(&pid) {
            return true;
        }
        if vid == MICROSOFT_VENDOR_ID && MICROSOFT_PRODUCT_IDS.contains(&pid) {
            return true;
        }
        if vid == ANKER_VENDOR_ID && ANKER_PRODUCT_IDS.contains(&pid) {
            return true;
        }
        if vid == UGREEN_VENDOR_ID && UGREEN_PRODUCT_IDS.contains(&pid) {
            return true;
        }
        if vid == REALTEK_VENDOR_ID {
            return true;
        }
        false
    }

    fn has_bulk_endpoints(cfg: &UsbConfiguration) -> bool {
        for iface in &cfg.interfaces {
            let mut has_bulk_in = false;
            let mut has_bulk_out = false;
            for ep in &iface.endpoints {
                if ep.is_bulk() {
                    if ep.is_in() {
                        has_bulk_in = true;
                    } else {
                        has_bulk_out = true;
                    }
                }
            }
            if has_bulk_in && has_bulk_out {
                return true;
            }
        }
        false
    }
}

impl UsbClassDriver for Rtl8152Driver {
    fn name(&self) -> &'static str {
        "rtl8152-eth"
    }

    fn priority(&self) -> u8 {
        15
    }

    fn matches(&self, dev: &UsbDevice, cfg: &UsbConfiguration, iface: &UsbInterfaceInfo) -> bool {
        if Self::is_supported_device(dev.vendor_id(), dev.product_id()) {
            return true;
        }
        if iface.iface.b_interface_class == GENERIC_USB_ETH_CLASS && Self::has_bulk_endpoints(cfg) {
            crate::log_info!(
                "[RTL8152] Generic USB Ethernet candidate: {:04x}:{:04x}",
                dev.vendor_id(),
                dev.product_id()
            );
            return true;
        }
        false
    }

    fn bind(&self, dev: &UsbDevice, cfg: &UsbConfiguration, _iface: &UsbInterfaceInfo) -> Result<(), &'static str> {
        crate::log_info!(
            "[RTL8152] Binding to {:04x}:{:04x} slot {}",
            dev.vendor_id(),
            dev.product_id(),
            dev.slot_id
        );

        let mut bulk_in_ep = 0u8;
        let mut bulk_out_ep = 0u8;

        for iface in &cfg.interfaces {
            for ep in &iface.endpoints {
                if ep.is_bulk() {
                    if ep.is_in() && bulk_in_ep == 0 {
                        bulk_in_ep = ep.b_endpoint_address;
                    } else if ep.is_out() && bulk_out_ep == 0 {
                        bulk_out_ep = ep.b_endpoint_address;
                    }
                }
            }
        }

        if bulk_in_ep == 0 || bulk_out_ep == 0 {
            return Err("No bulk endpoints found");
        }

        let mut eth_dev = Rtl8152Device::new(dev.slot_id);
        eth_dev.bulk_in_ep = bulk_in_ep;
        eth_dev.bulk_out_ep = bulk_out_ep;

        eth_dev.read_mac_address();

        crate::log_info!(
            "[RTL8152] MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            eth_dev.mac_address[0], eth_dev.mac_address[1], eth_dev.mac_address[2],
            eth_dev.mac_address[3], eth_dev.mac_address[4], eth_dev.mac_address[5]
        );

        if let Err(e) = eth_dev.init_device() {
            crate::log_warn!("[RTL8152] Init warning: {} (continuing anyway)", e);
        }

        eth_dev.connected.store(true, Ordering::Relaxed);

        let dev_static: &'static Rtl8152Device = Box::leak(Box::new(eth_dev));
        register_device(dev_static);

        RTL8152_CONNECTED.store(true, Ordering::Relaxed);
        crate::network::stack::set_network_connected(true);

        crate::log_info!("[RTL8152] USB Ethernet adapter registered with network stack");

        if let Some(stack) = crate::network::get_network_stack() {
            crate::log_info!("[RTL8152] Requesting DHCP...");
            match stack.request_dhcp() {
                Ok(lease) => {
                    crate::log_info!(
                        "[RTL8152] DHCP success: {}.{}.{}.{}",
                        lease.ip[0], lease.ip[1], lease.ip[2], lease.ip[3]
                    );
                }
                Err(e) => {
                    crate::log_warn!("[RTL8152] DHCP failed: {}", e);
                    crate::network::stack::set_network_connected(false);
                }
            }
        }

        Ok(())
    }

    fn unbind(&self, dev: &UsbDevice, _iface: &UsbInterfaceInfo) {
        crate::log_info!("[RTL8152] Unbinding from slot {}", dev.slot_id);
        RTL8152_CONNECTED.store(false, Ordering::Relaxed);
        crate::network::stack::set_network_connected(false);
    }
}

pub fn init() {
    crate::log::logger::log_critical("[RTL8152] Registering Realtek USB Ethernet driver");
    register_class_driver(Arc::new(Rtl8152Driver));
}

pub fn is_connected() -> bool {
    RTL8152_CONNECTED.load(Ordering::Relaxed)
}
