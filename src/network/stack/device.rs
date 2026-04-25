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

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use smoltcp::{
    phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant as SmolInstant,
    wire::{EthernetAddress, HardwareAddress},
};
use spin::Once;

use super::core::get_network_stack;

pub const DEFAULT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

pub trait SmolDevice: Send + Sync + 'static {
    fn now_ms(&self) -> u64;
    fn recv(&self) -> Option<Vec<u8>>;
    fn transmit(&self, frame: &[u8]) -> Result<(), ()>;
    fn mac(&self) -> [u8; 6];
    fn link_mtu(&self) -> usize {
        1500
    }
}

/// Counter for receive() calls within a single iface.poll() invocation.
/// Reset by poll_interface() before calling iface.poll().
pub(super) static RECV_CALL_COUNT: AtomicU32 = AtomicU32::new(0);

/// Maximum frames processed per single iface.poll() invocation.
/// Twice the RX ring size (32) is generous for normal traffic.
pub(super) const MAX_RECV_PER_POLL: u32 = 64;

pub(super) static DEVICE_SLOT: Once<&'static dyn SmolDevice> = Once::new();

pub fn register_device(dev: &'static dyn SmolDevice) {
    DEVICE_SLOT.call_once(|| dev);
    if let Some(stack) = get_network_stack() {
        let mac = dev.mac();
        let mut iface = stack.iface.lock();
        iface.set_hardware_addr(HardwareAddress::Ethernet(EthernetAddress(mac)));
    }
}

pub(super) fn now_ms() -> u64 {
    if let Some(dev) = DEVICE_SLOT.get() {
        return dev.now_ms();
    }
    crate::time::timestamp_millis()
}

pub struct SmolDeviceAdapter;

impl Device for SmolDeviceAdapter {
    type RxToken<'a> = RxT;
    type TxToken<'a> = TxT;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = DEVICE_SLOT.get().map(|d| d.link_mtu()).unwrap_or(1500);
        caps.medium = Medium::Ethernet;
        caps.checksum = ChecksumCapabilities::default();
        caps
    }

    fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Cap frames per iface.poll() to prevent infinite packet-bounce loops.
        let count = RECV_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
        if count >= MAX_RECV_PER_POLL {
            return None;
        }
        if let Some(dev) = DEVICE_SLOT.get() {
            if let Some(frame) = dev.recv() {
                crate::sys::serial::print(b"[NET] RX frame ");
                crate::sys::serial::print_dec(frame.len() as u64);
                crate::sys::serial::println(b" bytes");

                // Debug: Print TCP details for packets larger than ACKs
                if frame.len() > 60 && frame.len() >= 34 {
                    // Check if it's an IP packet (ethertype 0x0800)
                    if frame[12] == 0x08 && frame[13] == 0x00 {
                        let ip_header_len = ((frame[14] & 0x0F) as usize) * 4;
                        let protocol = frame[23]; // IP protocol
                        if protocol == 6 && frame.len() >= 14 + ip_header_len + 20 {
                            // TCP packet
                            let tcp_start = 14 + ip_header_len;
                            let tcp_header_len = ((frame[tcp_start + 12] >> 4) as usize) * 4;
                            let tcp_flags = frame[tcp_start + 13];
                            let payload_start = tcp_start + tcp_header_len;
                            let payload_len = frame.len().saturating_sub(payload_start);

                            crate::sys::serial::print(b"[NET] TCP flags=0x");
                            crate::sys::serial::print_hex(tcp_flags as u64);
                            crate::sys::serial::print(b" (");
                            if tcp_flags & 0x01 != 0 {
                                crate::sys::serial::print(b"FIN ");
                            }
                            if tcp_flags & 0x02 != 0 {
                                crate::sys::serial::print(b"SYN ");
                            }
                            if tcp_flags & 0x04 != 0 {
                                crate::sys::serial::print(b"RST ");
                            }
                            if tcp_flags & 0x08 != 0 {
                                crate::sys::serial::print(b"PSH ");
                            }
                            if tcp_flags & 0x10 != 0 {
                                crate::sys::serial::print(b"ACK ");
                            }
                            crate::sys::serial::print(b") payload=");
                            crate::sys::serial::print_dec(payload_len as u64);
                            crate::sys::serial::println(b"");

                            // Print first few bytes of TCP payload
                            if payload_len > 0 && payload_start < frame.len() {
                                crate::sys::serial::print(b"[NET] payload=");
                                for i in 0..8.min(payload_len) {
                                    crate::sys::serial::print_hex(frame[payload_start + i] as u64);
                                    crate::sys::serial::print(b" ");
                                }
                                crate::sys::serial::println(b"");
                            }
                        }
                    }
                }

                return Some((RxT(frame), TxT));
            }
        }
        None
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxT)
    }
}

pub struct RxT(pub Vec<u8>);

impl RxToken for RxT {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = self.0;
        f(&mut buf)
    }
}

pub struct TxT;

impl TxToken for TxT {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        crate::sys::serial::print(b"[NET] TxToken consume ");
        crate::sys::serial::print_dec(len as u64);
        crate::sys::serial::println(b" bytes");
        let mut out = vec![0u8; len];
        let res = f(&mut out);
        if let Some(dev) = DEVICE_SLOT.get() {
            if let Err(()) = dev.transmit(&out) {
                crate::sys::serial::println(b"[NET] TX FAILED - retrying");
                for retry in 0..3 {
                    core::hint::spin_loop();
                    if dev.transmit(&out).is_ok() {
                        crate::sys::serial::print(b"[NET] TX retry ");
                        crate::sys::serial::print_dec(retry as u64 + 1);
                        crate::sys::serial::println(b" succeeded");
                        break;
                    }
                }
            }
        } else {
            crate::sys::serial::println(b"[NET] TxToken: NO DEVICE!");
        }
        crate::sys::serial::println(b"[NET] TxToken done");
        res
    }
}
