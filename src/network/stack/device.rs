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
use spin::Once;
use smoltcp::{
    phy::{ChecksumCapabilities, DeviceCapabilities, Medium, RxToken, TxToken, Device},
    time::Instant as SmolInstant,
    wire::{EthernetAddress, HardwareAddress},
};

use super::core::get_network_stack;

pub const DEFAULT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

pub trait SmolDevice: Send + Sync + 'static {
    fn now_ms(&self) -> u64;
    fn recv(&self) -> Option<Vec<u8>>;
    fn transmit(&self, frame: &[u8]) -> Result<(), ()>;
    fn mac(&self) -> [u8; 6];
    fn link_mtu(&self) -> usize { 1500 }
}

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
        if let Some(dev) = DEVICE_SLOT.get() {
            if let Some(frame) = dev.recv() {
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
        let mut out = vec![0u8; len];
        let res = f(&mut out);
        if let Some(dev) = DEVICE_SLOT.get() {
            let _ = dev.transmit(&out);
        }
        res
    }
}
