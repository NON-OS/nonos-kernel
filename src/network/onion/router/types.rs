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


use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::network::onion::OnionError;

#[derive(Debug)]
pub struct RelayStats {
    pub cells_processed: AtomicU32,
    pub bytes_relayed: AtomicU32,
    pub circuits_created: AtomicU32,
    pub streams_opened: AtomicU32,
}

impl RelayStats {
    pub fn new() -> Self {
        Self {
            cells_processed: AtomicU32::new(0),
            bytes_relayed: AtomicU32::new(0),
            circuits_created: AtomicU32::new(0),
            streams_opened: AtomicU32::new(0),
        }
    }

    pub fn inc_cells(&self) {
        self.cells_processed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_circuits(&self) {
        self.circuits_created.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_streams(&self) {
        self.streams_opened.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes(&self, bytes: u32) {
        self.bytes_relayed.fetch_add(bytes, Ordering::Relaxed);
    }
}

impl Clone for RelayStats {
    fn clone(&self) -> Self {
        Self {
            cells_processed: AtomicU32::new(self.cells_processed.load(Ordering::Relaxed)),
            bytes_relayed: AtomicU32::new(self.bytes_relayed.load(Ordering::Relaxed)),
            circuits_created: AtomicU32::new(self.circuits_created.load(Ordering::Relaxed)),
            streams_opened: AtomicU32::new(self.streams_opened.load(Ordering::Relaxed)),
        }
    }
}

impl Default for RelayStats {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RelayKeys {
    pub ed25519_secret: [u8; 32],
    pub ed25519_public: [u8; 32],

    pub ntor_secret: [u8; 32],
    pub ntor_public: [u8; 32],

    pub tls_secret: Vec<u8>,
    pub tls_public: Vec<u8>,

    pub generated_at: u64,

    pub initialized: bool,
}

impl Default for RelayKeys {
    fn default() -> Self {
        Self {
            ed25519_secret: [0u8; 32],
            ed25519_public: [0u8; 32],
            ntor_secret: [0u8; 32],
            ntor_public: [0u8; 32],
            tls_secret: Vec::new(),
            tls_public: Vec::new(),
            generated_at: 0,
            initialized: false,
        }
    }
}

pub struct KeyManager {
    pub rsa_keys: Vec<u8>,
    pub relay_keys: RelayKeys,
}

impl KeyManager {
    pub fn new() -> Self {
        Self {
            rsa_keys: Vec::new(),
            relay_keys: RelayKeys::default(),
        }
    }

    pub fn generate_relay_keys(&mut self) -> Result<(), OnionError> {
        let mut ed_seed = [0u8; 32];
        crate::crypto::fill_random_bytes(&mut ed_seed);

        let ed_keypair = crate::crypto::ed25519::KeyPair::from_seed(ed_seed);
        self.relay_keys.ed25519_secret.copy_from_slice(&ed_seed);
        self.relay_keys.ed25519_public.copy_from_slice(&ed_keypair.public);

        let mut ntor_secret = [0u8; 32];
        crate::crypto::fill_random_bytes(&mut ntor_secret);

        ntor_secret[0] &= 248;
        ntor_secret[31] &= 127;
        ntor_secret[31] |= 64;

        let ntor_public = crate::crypto::curve25519::scalarmult_base(&ntor_secret);
        self.relay_keys.ntor_secret.copy_from_slice(&ntor_secret);
        self.relay_keys.ntor_public.copy_from_slice(&ntor_public);

        let mut tls_seed = [0u8; 32];
        crate::crypto::fill_random_bytes(&mut tls_seed);
        let tls_keypair = crate::crypto::ed25519::KeyPair::from_seed(tls_seed);
        self.relay_keys.tls_secret = tls_seed.to_vec();
        self.relay_keys.tls_public = tls_keypair.public.to_vec();

        self.relay_keys.generated_at = crate::time::timestamp_secs();
        self.relay_keys.initialized = true;

        crate::crypto::secure_zero(&mut ed_seed);
        crate::crypto::secure_zero(&mut ntor_secret);
        crate::crypto::secure_zero(&mut tls_seed);

        crate::log::info!("keymanager: relay keys generated");
        Ok(())
    }

    pub fn ed25519_identity(&self) -> Option<&[u8; 32]> {
        if self.relay_keys.initialized {
            Some(&self.relay_keys.ed25519_public)
        } else {
            None
        }
    }

    pub fn ntor_onion_key(&self) -> Option<&[u8; 32]> {
        if self.relay_keys.initialized {
            Some(&self.relay_keys.ntor_public)
        } else {
            None
        }
    }

    pub fn has_relay_keys(&self) -> bool {
        self.relay_keys.initialized
    }

    pub fn rotate_ntor_key(&mut self) -> Result<(), OnionError> {
        if !self.relay_keys.initialized {
            return Err(OnionError::InvalidState);
        }

        let mut new_secret = [0u8; 32];
        crate::crypto::fill_random_bytes(&mut new_secret);

        new_secret[0] &= 248;
        new_secret[31] &= 127;
        new_secret[31] |= 64;

        let new_public = crate::crypto::curve25519::scalarmult_base(&new_secret);

        crate::crypto::secure_zero(&mut self.relay_keys.ntor_secret);

        self.relay_keys.ntor_secret.copy_from_slice(&new_secret);
        self.relay_keys.ntor_public.copy_from_slice(&new_public);

        crate::crypto::secure_zero(&mut new_secret);

        crate::log::info!("keymanager: ntor key rotated");
        Ok(())
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RouteOptimizer {
    pub cached_paths: Vec<u8>,
}

impl RouteOptimizer {
    pub fn new() -> Self {
        Self { cached_paths: Vec::new() }
    }
}

impl Default for RouteOptimizer {
    fn default() -> Self {
        Self::new()
    }
}
