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

//! WiFi network stack bridge for smoltcp integration.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::api::get_device;
use super::device::WifiState;
use super::error::WifiError;

const WIFI_MTU: usize = 1500;
const FALLBACK_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x04];

static BRIDGE_REGISTERED: AtomicBool = AtomicBool::new(false);
static TX_PACKETS: AtomicU64 = AtomicU64::new(0);
static RX_PACKETS: AtomicU64 = AtomicU64::new(0);
static TX_BYTES: AtomicU64 = AtomicU64::new(0);
static RX_BYTES: AtomicU64 = AtomicU64::new(0);
static TX_ERRORS: AtomicU64 = AtomicU64::new(0);
static RX_ERRORS: AtomicU64 = AtomicU64::new(0);

pub struct WiFiSmolBridge;

impl crate::network::stack::SmolDevice for WiFiSmolBridge {
    fn now_ms(&self) -> u64 {
        crate::time::timestamp_millis()
    }

    fn recv(&self) -> Option<Vec<u8>> {
        let dev = get_device()?;
        let mut guard = dev.lock();

        if guard.state() != WifiState::Connected {
            return None;
        }

        match guard.receive() {
            Ok(Some(data)) => {
                RX_PACKETS.fetch_add(1, Ordering::Relaxed);
                RX_BYTES.fetch_add(data.len() as u64, Ordering::Relaxed);
                Some(data)
            }
            Ok(None) => None,
            Err(_) => {
                RX_ERRORS.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    fn transmit(&self, frame: &[u8]) -> Result<(), ()> {
        let dev = get_device().ok_or(())?;
        let mut guard = dev.lock();

        if guard.state() != WifiState::Connected {
            return Err(());
        }

        match guard.transmit(frame) {
            Ok(()) => {
                TX_PACKETS.fetch_add(1, Ordering::Relaxed);
                TX_BYTES.fetch_add(frame.len() as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(_) => {
                TX_ERRORS.fetch_add(1, Ordering::Relaxed);
                Err(())
            }
        }
    }

    fn mac(&self) -> [u8; 6] {
        if let Some(dev) = get_device() {
            let guard = dev.lock();
            guard.mac_address()
        } else {
            FALLBACK_MAC
        }
    }

    fn link_mtu(&self) -> usize {
        WIFI_MTU
    }
}

pub static WIFI_SMOL_BRIDGE: WiFiSmolBridge = WiFiSmolBridge;

pub fn register_with_network_stack() -> Result<(), WifiError> {
    if BRIDGE_REGISTERED.load(Ordering::SeqCst) {
        return Ok(());
    }

    let dev = get_device().ok_or(WifiError::NotInitialized)?;

    {
        let guard = dev.lock();
        if guard.state() != WifiState::Connected {
            return Err(WifiError::NotConnected);
        }
    }

    crate::network::stack::register_device(&WIFI_SMOL_BRIDGE);
    BRIDGE_REGISTERED.store(true, Ordering::SeqCst);
    crate::log::info!("iwlwifi: Registered with network stack");

    Ok(())
}

pub fn unregister_from_network_stack() {
    if BRIDGE_REGISTERED.load(Ordering::SeqCst) {
        BRIDGE_REGISTERED.store(false, Ordering::SeqCst);
        reset_stats();
    }
}

pub fn is_registered() -> bool {
    BRIDGE_REGISTERED.load(Ordering::Relaxed)
}

pub fn reset_stats() {
    TX_PACKETS.store(0, Ordering::Relaxed);
    RX_PACKETS.store(0, Ordering::Relaxed);
    TX_BYTES.store(0, Ordering::Relaxed);
    RX_BYTES.store(0, Ordering::Relaxed);
    TX_ERRORS.store(0, Ordering::Relaxed);
    RX_ERRORS.store(0, Ordering::Relaxed);
}

#[derive(Debug, Clone, Default)]
pub struct WiFiStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub connected: bool,
    pub rssi: i8,
    pub channel: u8,
}

impl WiFiStats {
    pub fn current() -> Self {
        let (connected, rssi, channel) = if let Some(dev) = get_device() {
            let guard = dev.lock();
            let connected = guard.state() == WifiState::Connected;
            let (rssi, channel) = if connected {
                if let Some(info) = guard.get_link_info() {
                    (info.rssi, info.channel)
                } else {
                    (0, 0)
                }
            } else {
                (0, 0)
            };
            (connected, rssi, channel)
        } else {
            (false, 0, 0)
        };

        Self {
            rx_packets: RX_PACKETS.load(Ordering::Relaxed),
            tx_packets: TX_PACKETS.load(Ordering::Relaxed),
            rx_bytes: RX_BYTES.load(Ordering::Relaxed),
            tx_bytes: TX_BYTES.load(Ordering::Relaxed),
            rx_errors: RX_ERRORS.load(Ordering::Relaxed),
            tx_errors: TX_ERRORS.load(Ordering::Relaxed),
            connected,
            rssi,
            channel,
        }
    }

    pub fn total_packets(&self) -> u64 {
        self.rx_packets + self.tx_packets
    }

    pub fn total_bytes(&self) -> u64 {
        self.rx_bytes + self.tx_bytes
    }

    pub fn total_errors(&self) -> u64 {
        self.rx_errors + self.tx_errors
    }
}
