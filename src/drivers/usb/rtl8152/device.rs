// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

use crate::drivers::usb::get_manager;
use crate::network::stack::SmolDevice;

use super::constants::*;

pub struct Rtl8152Device {
    pub slot_id: u8,
    pub bulk_in_ep: u8,
    pub bulk_out_ep: u8,
    pub mac_address: [u8; 6],
    pub mtu: usize,
    pub connected: AtomicBool,
    pub rx_queue: Mutex<Vec<Vec<u8>>>,
    pub link_up: AtomicBool,
    pub rx_bytes: AtomicUsize,
    pub tx_bytes: AtomicUsize,
}

impl Rtl8152Device {
    pub fn new(slot_id: u8) -> Self {
        Self {
            slot_id,
            bulk_in_ep: 0,
            bulk_out_ep: 0,
            mac_address: [0; 6],
            mtu: RTL8152_MTU,
            connected: AtomicBool::new(false),
            rx_queue: Mutex::new(Vec::new()),
            link_up: AtomicBool::new(false),
            rx_bytes: AtomicUsize::new(0),
            tx_bytes: AtomicUsize::new(0),
        }
    }

    pub fn read_mac_address(&mut self) -> bool {
        if let Some(mgr) = get_manager() {
            let mut mac_buf = [0u8; 8];

            if mgr.control_in(
                self.slot_id,
                RTL_VENDOR_READ,
                RTL_REQ_GET_REGS,
                RTL_REG_MAC,
                RTL_PLA_BASE,
                &mut mac_buf,
            ).is_ok() {
                self.mac_address.copy_from_slice(&mac_buf[..6]);

                if self.mac_address != [0; 6] && self.mac_address != [0xFF; 6] {
                    return true;
                }
            }

            for string_idx in 3..=6u8 {
                if let Ok(mac_str) = mgr.get_string_descriptor(self.slot_id, string_idx) {
                    if let Some(mac) = parse_mac_string(&mac_str) {
                        self.mac_address = mac;
                        return true;
                    }
                }
            }
        }

        self.mac_address = [
            0x02,
            0x00,
            0x52,
            0x54,
            0x4C,
            self.slot_id,
        ];
        true
    }

    pub fn init_device(&mut self) -> Result<(), &'static str> {
        if let Some(mgr) = get_manager() {
            mgr.control_out(
                self.slot_id,
                RTL_VENDOR_WRITE,
                RTL_REQ_SET_REGS,
                RTL_REG_CTRL,
                RTL_PLA_BASE,
                &[RTL_CTRL_RESET],
            ).map_err(|_| "Failed to reset device")?;

            crate::time::delay_ms(100);

            let rx_cfg = (RTL_RX_ACCEPT_PHYS | RTL_RX_ACCEPT_BROADCAST).to_le_bytes();
            mgr.control_out(
                self.slot_id,
                RTL_VENDOR_WRITE,
                RTL_REQ_SET_REGS,
                RTL_REG_RX_CFG,
                RTL_PLA_BASE,
                &rx_cfg,
            ).map_err(|_| "Failed to set RX config")?;

            mgr.control_out(
                self.slot_id,
                RTL_VENDOR_WRITE,
                RTL_REQ_SET_REGS,
                RTL_REG_CTRL,
                RTL_PLA_BASE,
                &[RTL_CTRL_START],
            ).map_err(|_| "Failed to start device")?;

            self.link_up.store(true, Ordering::Relaxed);
            Ok(())
        } else {
            Err("USB manager not available")
        }
    }

    pub fn poll_rx(&self) {
        if !self.connected.load(Ordering::Relaxed) {
            return;
        }

        if let Some(mgr) = get_manager() {
            let mut buffer = [0u8; RTL8152_RX_BUF_SIZE];
            match mgr.bulk_in(self.slot_id, self.bulk_in_ep, &mut buffer) {
                Ok(len) if len > 4 => {
                    let packets = self.parse_rx_packets(&buffer[..len]);

                    let mut queue = self.rx_queue.lock();
                    for pkt in packets {
                        self.rx_bytes.fetch_add(pkt.len(), Ordering::Relaxed);
                        if queue.len() < 64 {
                            queue.push(pkt);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn parse_rx_packets(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let mut offset = 0;

        while offset + 4 <= data.len() {
            let pkt_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            let _flags = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);

            offset += 4;

            if pkt_len == 0 || pkt_len > 1518 {
                break;
            }

            if offset + pkt_len <= data.len() {
                if pkt_len >= 14 {
                    packets.push(data[offset..offset + pkt_len].to_vec());
                }
                offset += pkt_len;
                offset = (offset + 7) & !7;
            } else {
                break;
            }
        }

        if packets.is_empty() && data.len() >= 14 {
            packets.push(data.to_vec());
        }

        packets
    }

    fn wrap_tx_packet(&self, frame: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(frame.len() + 8);

        let len = frame.len() as u32;
        packet.extend_from_slice(&len.to_le_bytes());
        packet.extend_from_slice(&0u32.to_le_bytes());
        packet.extend_from_slice(frame);

        packet
    }
}

impl SmolDevice for Rtl8152Device {
    fn now_ms(&self) -> u64 {
        crate::time::timestamp_millis()
    }

    fn recv(&self) -> Option<Vec<u8>> {
        let mut queue = self.rx_queue.lock();
        if queue.is_empty() {
            drop(queue);
            self.poll_rx();
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
            let packet = self.wrap_tx_packet(frame);

            match mgr.bulk_out(self.slot_id, self.bulk_out_ep, &packet) {
                Ok(_) => {
                    self.tx_bytes.fetch_add(frame.len(), Ordering::Relaxed);
                    Ok(())
                }
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
