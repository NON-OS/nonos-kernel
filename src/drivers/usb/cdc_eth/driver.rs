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

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::drivers::usb::{
    UsbClassDriver, UsbDevice, UsbConfiguration, UsbInterfaceInfo,
    interface_matches, register_class_driver, get_manager,
};
use crate::network::stack::register_device;

use super::constants::{
    CDC_CLASS, CDC_DATA_CLASS, CDC_SUBCLASS_ECM, CDC_SUBCLASS_NCM,
    CDC_GET_NTB_PARAMETERS,
};
use super::device::CdcEthDevice;

pub struct CdcEthDriver;

impl UsbClassDriver for CdcEthDriver {
    fn name(&self) -> &'static str {
        "cdc-ether"
    }

    fn priority(&self) -> u8 {
        10
    }

    fn matches(&self, _dev: &UsbDevice, _cfg: &UsbConfiguration, iface: &UsbInterfaceInfo) -> bool {
        interface_matches(iface, CDC_CLASS, Some(CDC_SUBCLASS_ECM), None) ||
        interface_matches(iface, CDC_CLASS, Some(CDC_SUBCLASS_NCM), None)
    }

    fn bind(&self, dev: &UsbDevice, cfg: &UsbConfiguration, iface: &UsbInterfaceInfo) -> Result<(), &'static str> {
        let is_ncm = iface.iface.b_interface_sub_class == CDC_SUBCLASS_NCM;
        let control_iface = iface.iface.b_interface_number;

        crate::log_info!(
            "[CDC-ETH] Binding {} to slot {} interface {}",
            if is_ncm { "NCM" } else { "ECM" },
            dev.slot_id,
            control_iface
        );

        let data_iface = cfg.interfaces.iter()
            .find(|i| interface_matches(i, CDC_DATA_CLASS, None, None))
            .ok_or("No CDC data interface found")?;

        let bulk_in = data_iface.endpoints.iter()
            .find(|e| e.is_bulk() && e.is_in())
            .ok_or("No bulk IN endpoint")?;
        let bulk_out = data_iface.endpoints.iter()
            .find(|e| e.is_bulk() && e.is_out())
            .ok_or("No bulk OUT endpoint")?;

        let interrupt_ep = iface.endpoints.iter()
            .find(|e| e.is_interrupt() && e.is_in())
            .map(|e| e.b_endpoint_address)
            .unwrap_or(0);

        let mut eth_dev = CdcEthDevice::new(dev.slot_id, is_ncm);
        eth_dev.control_iface = control_iface;
        eth_dev.data_iface = data_iface.iface.b_interface_number;
        eth_dev.bulk_in_ep = bulk_in.b_endpoint_address;
        eth_dev.bulk_out_ep = bulk_out.b_endpoint_address;
        eth_dev.interrupt_ep = interrupt_ep;

        eth_dev.read_mac_from_descriptor(dev);

        crate::log_info!(
            "[CDC-ETH] MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            eth_dev.mac_address[0], eth_dev.mac_address[1], eth_dev.mac_address[2],
            eth_dev.mac_address[3], eth_dev.mac_address[4], eth_dev.mac_address[5]
        );

        if is_ncm {
            if let Some(mgr) = get_manager() {
                let mut params = [0u8; 28];
                if mgr.control_in(
                    dev.slot_id,
                    0xA1,
                    CDC_GET_NTB_PARAMETERS,
                    0,
                    control_iface as u16,
                    &mut params,
                ).is_ok() {
                    let ntb_in_max = u32::from_le_bytes([params[4], params[5], params[6], params[7]]);
                    crate::log_info!("[CDC-ETH] NCM max NTB size: {} bytes", ntb_in_max);
                }
            }
        }

        eth_dev.setup_packet_filter()?;

        eth_dev.connected.store(true, Ordering::Relaxed);

        let dev_static: &'static CdcEthDevice = Box::leak(Box::new(eth_dev));
        register_device(dev_static);

        crate::network::stack::set_network_connected(true);

        crate::log_info!("[CDC-ETH] USB Ethernet adapter registered with network stack");

        if let Some(stack) = crate::network::get_network_stack() {
            crate::log_info!("[CDC-ETH] Requesting DHCP...");
            match stack.request_dhcp() {
                Ok(lease) => {
                    crate::log_info!(
                        "[CDC-ETH] DHCP success: {}.{}.{}.{}",
                        lease.ip[0], lease.ip[1], lease.ip[2], lease.ip[3]
                    );
                }
                Err(e) => {
                    crate::log_warn!("[CDC-ETH] DHCP failed: {}", e);
                }
            }
        }

        Ok(())
    }

    fn unbind(&self, dev: &UsbDevice, _iface: &UsbInterfaceInfo) {
        crate::log_info!("[CDC-ETH] Unbinding from slot {}", dev.slot_id);
        crate::network::stack::set_network_connected(false);
    }
}

pub fn init() {
    crate::log_info!("[CDC-ETH] Registering USB CDC Ethernet driver");
    register_class_driver(Arc::new(CdcEthDriver));
}

pub fn is_connected() -> bool {
    crate::network::is_network_available()
}
