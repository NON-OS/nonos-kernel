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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

use crate::drivers::usb::{UsbDevice, get_manager};
use crate::network::stack::SmolDevice;

use super::constants::{CDC_SET_ETHERNET_PKT_FILTER, PACKET_TYPE_DIRECTED, PACKET_TYPE_BROADCAST, PACKET_TYPE_MULTICAST};
use super::ncm::{wrap_ntb, unwrap_ntb};

pub struct CdcEthDevice {
    pub slot_id: u8,
    pub control_iface: u8,
    pub data_iface: u8,
    pub bulk_in_ep: u8,
    pub bulk_out_ep: u8,
    pub interrupt_ep: u8,
    pub mac_address: [u8; 6],
    pub mtu: usize,
    pub is_ncm: bool,
    pub connected: AtomicBool,
    pub rx_queue: Mutex<Vec<Vec<u8>>>,
    pub tx_pending: AtomicUsize,
}

impl CdcEthDevice {
    pub fn new(slot_id: u8, is_ncm: bool) -> Self {
        Self {
            slot_id,
            control_iface: 0,
            data_iface: 0,
            bulk_in_ep: 0,
            bulk_out_ep: 0,
            interrupt_ep: 0,
            mac_address: [0; 6],
            mtu: 1500,
            is_ncm,
            connected: AtomicBool::new(false),
            rx_queue: Mutex::new(Vec::new()),
            tx_pending: AtomicUsize::new(0),
        }
    }

    pub fn poll_rx(&self) {
        if !self.connected.load(Ordering::Relaxed) {
            return;
        }

        if let Some(mgr) = get_manager() {
            let mut buffer = [0u8; 2048];
            match mgr.bulk_in(self.slot_id, self.bulk_in_ep, &mut buffer) {
                Ok(len) if len > 0 => {
                    let data = &buffer[..len];
                    let packets = if self.is_ncm {
                        unwrap_ntb(data)
                    } else {
                        if len >= 14 {
                            alloc::vec![data.to_vec()]
                        } else {
                            alloc::vec![]
                        }
                    };

                    let mut queue = self.rx_queue.lock();
                    for pkt in packets {
                        if queue.len() < 64 {
                            queue.push(pkt);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    pub fn setup_packet_filter(&self) -> Result<(), &'static str> {
        if let Some(mgr) = get_manager() {
            let filter = PACKET_TYPE_DIRECTED | PACKET_TYPE_BROADCAST | PACKET_TYPE_MULTICAST;

            mgr.control_out(
                self.slot_id,
                0x21,
                CDC_SET_ETHERNET_PKT_FILTER,
                filter,
                self.control_iface as u16,
                &[],
            ).map_err(|_| "Failed to set packet filter")?;

            Ok(())
        } else {
            Err("USB manager not available")
        }
    }

    pub fn read_mac_from_descriptor(&mut self, dev: &UsbDevice) -> bool {
        if let Some(mgr) = get_manager() {
            for string_idx in 3..=6u8 {
                if let Ok(mac_str) = mgr.get_string_descriptor(dev.slot_id, string_idx) {
                    if mac_str.len() == 12 || mac_str.len() == 17 {
                        if let Some(mac) = parse_mac_string(&mac_str) {
                            self.mac_address = mac;
                            return true;
                        }
                    }
                }
            }
        }

        self.mac_address = [
            0x02,
            0x00,
            0x4E,
            0x4F,
            0x4E,
            dev.slot_id,
        ];
        true
    }
}

impl SmolDevice for CdcEthDevice {
    fn now_ms(&self) -> u64 {
        crate::time::timestamp_millis()
    }

    fn recv(&self) -> Option<Vec<u8>> {
        let mut queue = self.rx_queue.lock();
        if queue.is_empty() {
            self.poll_rx();
            drop(queue);
            let mut queue = self.rx_queue.lock();
            queue.pop()
        } else {
            queue.pop()
        }
    }

    fn transmit(&self, frame: &[u8]) -> Result<(), ()> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(());
        }

        if let Some(mgr) = get_manager() {
            let packet = if self.is_ncm {
                wrap_ntb(frame)
            } else {
                frame.to_vec()
            };

            match mgr.bulk_out(self.slot_id, self.bulk_out_ep, &packet) {
                Ok(_) => Ok(()),
                Err(_) => Err(()),
            }
        } else {
            Err(())
        }
    }

    fn mac(&self) -> [u8; 6] {
        self.mac_address
    }

    fn link_mtu(&self) -> usize {
        self.mtu
    }
}

fn parse_mac_string(s: &str) -> Option<[u8; 6]> {
    let clean: alloc::string::String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() != 12 {
        return None;
    }

    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(mac)
}
