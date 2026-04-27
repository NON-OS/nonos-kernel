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

use alloc::collections::BTreeMap;
use alloc::vec;
use core::sync::atomic::AtomicU32;
use spin::{Mutex, Once};

use smoltcp::{
    iface::{Config as IfaceConfig, Interface, Routes, SocketSet},
    time::Instant as SmolInstant,
    wire::{
        EthernetAddress, HardwareAddress, IpAddress as SmolIpAddress, IpCidr,
        Ipv4Address as SmolIpv4Address, Ipv6Address as SmolIpv6Address,
    },
};

use super::device::{now_ms, SmolDeviceAdapter, DEFAULT_MAC};
use super::types::{ConnectionEntry, Ipv4Address, Ipv6Address, NetworkStats};
use crate::crypto::util::rng::{get_entropy64, random_u64};

static STACK: Once<NetworkStack> = Once::new();

const DEFAULT_DNS_V6: [u8; 16] = [
    0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88,
];

pub struct NetworkStack {
    pub(crate) iface: Mutex<Interface>,
    pub(crate) sockets: Mutex<SocketSet<'static>>,
    pub(crate) routes: Mutex<Routes>,
    pub(super) conns: Mutex<BTreeMap<u32, ConnectionEntry>>,
    pub(crate) next_id: AtomicU32,
    pub(crate) stats: Mutex<NetworkStats>,
    pub(crate) default_dns_v4: Mutex<Ipv4Address>,
    pub(crate) gateway_v4: Mutex<Option<[u8; 4]>>,
    pub(crate) gateway_v6: Mutex<Option<[u8; 16]>>,
    pub(crate) default_dns_v6: Mutex<Ipv6Address>,
}

pub fn init_network_stack() {
    STACK.call_once(|| {
        let mut dev = SmolDeviceAdapter;
        let mut cfg = IfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(DEFAULT_MAC)));

        // Seed smoltcp with hardware entropy for TCP ISN generation.
        // Uses CSPRNG (ChaCha20) → VirtIO-RNG → RDSEED → RDRAND → TSC fallback waterfall.
        let seed = random_u64();
        // Verify seed is not trivially zero or the old hardcoded value (0xD1E5_7A2C)
        let seed = if seed == 0 || seed == 0xD1E5_7A2C {
            let fallback = get_entropy64();
            crate::log_warn!("[NET] Primary RNG returned weak seed, using entropy fallback");
            fallback
        } else {
            seed
        };
        cfg.random_seed = seed;
        crate::log_info!("[NET] smoltcp seeded with hardware entropy");

        let mut iface = Interface::new(cfg, &mut dev, SmolInstant::from_millis(now_ms() as i64));

        iface.update_ip_addrs(|ips| {
            if let Err(_) =
                ips.push(IpCidr::new(SmolIpAddress::Ipv4(SmolIpv4Address::new(127, 0, 0, 1)), 8))
            {
                crate::log::error!("network: failed to configure loopback v4");
            }
            if let Err(_) =
                ips.push(IpCidr::new(SmolIpAddress::Ipv6(SmolIpv6Address::LOOPBACK), 128))
            {
                crate::log::error!("network: failed to configure loopback v6");
            }
        });

        NetworkStack {
            iface: Mutex::new(iface),
            sockets: Mutex::new(SocketSet::new(vec![])),
            routes: Mutex::new(Routes::new()),
            conns: Mutex::new(BTreeMap::new()),
            next_id: AtomicU32::new(1),
            stats: Mutex::new(NetworkStats::default()),
            default_dns_v4: Mutex::new([10, 0, 2, 3]),
            gateway_v4: Mutex::new(None),
            gateway_v6: Mutex::new(None),
            default_dns_v6: Mutex::new(DEFAULT_DNS_V6),
        }
    });
}

pub fn get_network_stack() -> Option<&'static NetworkStack> {
    STACK.get()
}

impl NetworkStack {
    /// Maximum rounds of re-polling when a burst saturates `MAX_RECV_PER_POLL`.
    const MAX_POLL_ROUNDS: u32 = 3;

    #[inline]
    pub fn poll_interface(&self) {
        let mut iface = self.iface.lock();
        let mut sockets = self.sockets.lock();

        for _ in 0..Self::MAX_POLL_ROUNDS {
            let ts = SmolInstant::from_millis(now_ms() as i64);
            super::device::RECV_CALL_COUNT.store(0, core::sync::atomic::Ordering::Relaxed);
            let _activity = iface.poll(ts, &mut SmolDeviceAdapter, &mut *sockets);

            let consumed =
                super::device::RECV_CALL_COUNT.load(core::sync::atomic::Ordering::Relaxed);
            if consumed < super::device::MAX_RECV_PER_POLL {
                break;
            }
        }

        drop(sockets);
        drop(iface);
    }

    #[inline]
    pub(crate) fn poll(&self) {
        self.poll_interface();
    }

    /// Non-blocking variant for timer-IRQ context. Returns false if either
    /// the iface or sockets lock is contended (desktop thread is mid-poll),
    /// in which case the caller must skip this tick to avoid deadlock.
    #[inline]
    pub fn try_poll_interface(&self) -> bool {
        let mut iface = match self.iface.try_lock() {
            Some(g) => g,
            None => return false,
        };
        let mut sockets = match self.sockets.try_lock() {
            Some(g) => g,
            None => return false,
        };
        let ts = SmolInstant::from_millis(now_ms() as i64);
        let _ = iface.poll(ts, &mut SmolDeviceAdapter, &mut *sockets);
        true
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::util::rng::{get_entropy64, random_u64};

    /// The old hardcoded seed value that was a security vulnerability.
    const OLD_HARDCODED_SEED: u64 = 0xD1E5_7A2C;

    // ── Seed validation logic ────────────────────────────────────────────

    /// Verify the seed rejection logic: zero and the old hardcoded value
    /// must be detected and replaced with fallback entropy.
    #[test]
    fn test_seed_zero_is_rejected() {
        let seed: u64 = 0;
        let is_weak = seed == 0 || seed == OLD_HARDCODED_SEED;
        assert!(is_weak, "zero seed must be detected as weak");
    }

    #[test]
    fn test_old_hardcoded_seed_is_rejected() {
        let seed: u64 = OLD_HARDCODED_SEED;
        let is_weak = seed == 0 || seed == OLD_HARDCODED_SEED;
        assert!(is_weak, "old hardcoded seed must be detected as weak");
    }

    #[test]
    fn test_valid_seed_accepted() {
        let seed: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let is_weak = seed == 0 || seed == OLD_HARDCODED_SEED;
        assert!(!is_weak, "non-trivial seed should be accepted");
    }

    // ── RNG functions used for seeding ───────────────────────────────────

    #[test]
    fn test_random_u64_not_hardcoded() {
        let seed = random_u64();
        assert_ne!(seed, OLD_HARDCODED_SEED, "random_u64 must not return the old hardcoded value");
    }

    #[test]
    fn test_random_u64_varies() {
        let a = random_u64();
        let b = random_u64();
        // Extremely unlikely to collide (2^-64 probability)
        assert_ne!(a, b, "two random_u64 calls should return different values");
    }

    #[test]
    fn test_get_entropy64_not_zero() {
        let v = get_entropy64();
        // The fallback waterfall should always produce non-zero
        assert_ne!(v, 0, "get_entropy64 should not return zero");
    }

    #[test]
    fn test_get_entropy64_not_hardcoded() {
        let v = get_entropy64();
        assert_ne!(v, OLD_HARDCODED_SEED, "get_entropy64 must not return old hardcoded seed");
    }

    // ── Seed selection logic (mirrors init_network_stack) ────────────────

    /// Simulate the seed selection logic from init_network_stack
    fn select_seed(primary: u64) -> u64 {
        if primary == 0 || primary == OLD_HARDCODED_SEED {
            get_entropy64() // fallback
        } else {
            primary
        }
    }

    #[test]
    fn test_select_seed_rejects_zero() {
        let seed = select_seed(0);
        assert_ne!(seed, 0, "zero primary should trigger fallback");
    }

    #[test]
    fn test_select_seed_rejects_hardcoded() {
        let seed = select_seed(OLD_HARDCODED_SEED);
        // Fallback entropy should differ from OLD_HARDCODED_SEED
        // (astronomically unlikely to match)
        assert_ne!(seed, OLD_HARDCODED_SEED, "hardcoded primary should trigger fallback");
    }

    #[test]
    fn test_select_seed_accepts_valid() {
        let valid_seed: u64 = 0x1234_5678_9ABC_DEF0;
        let seed = select_seed(valid_seed);
        assert_eq!(seed, valid_seed, "valid primary should pass through unchanged");
    }
}
