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

use alloc::{collections::BTreeMap, string::String};
use core::sync::atomic::{AtomicBool, AtomicU64};
use spin::{Mutex, RwLock};

use crate::crypto::ethereum::EthAddress;
use crate::crypto::hash::blake3_hash;

use super::types::{CapsuleStore, CapsuleCategory, CapsuleMetadata, InstalledCapsule};

pub(super) static CAPSULE_STORE: Mutex<Option<CapsuleStore>> = Mutex::new(None);

pub fn init() {
    let store = CapsuleStore {
        available: RwLock::new(BTreeMap::new()),
        installed: RwLock::new(BTreeMap::new()),
        pending_installs: RwLock::new(BTreeMap::new()),
        wallet: RwLock::new(None),
        nonce: AtomicU64::new(0),
        fee_receiver: EthAddress([
            0x0a, 0x26, 0xc8, 0x0B, 0xe4, 0xE0, 0x60, 0xe6,
            0x88, 0xd7, 0xC2, 0x3a, 0xDD, 0xB9, 0x2c, 0xBb,
            0x5D, 0x2C, 0x9e, 0xCA
        ]),
    };

    register_system_capsules(&store);

    let mut lock = CAPSULE_STORE.lock();
    *lock = Some(store);
}

fn register_system_capsules(store: &CapsuleStore) {
    let system_capsules = [
        ("core", "1.0.0", "Core system services", CapsuleCategory::System, 0),
        ("shell", "1.0.0", "Terminal and command processing", CapsuleCategory::System, 0),
        ("graphics", "1.0.0", "Display and rendering engine", CapsuleCategory::System, 0),
        ("network", "1.0.0", "TCP/IP and onion routing", CapsuleCategory::Network, 0),
        ("vault", "1.0.0", "Cryptographic key storage", CapsuleCategory::Security, 0),
    ];

    let mut available = store.available.write();
    let mut installed = store.installed.write();

    for (name, version, desc, category, fee) in system_capsules {
        let id = blake3_hash(name.as_bytes());
        let meta = CapsuleMetadata {
            id,
            name: String::from(name),
            version: String::from(version),
            description: String::from(desc),
            author: String::from("NONOS Foundation"),
            category,
            size_bytes: 0,
            nox_fee: fee,
            signature: [0u8; 64],
            ed25519_pubkey: [0u8; 32],
            dilithium_signature: None,
        };

        available.insert(id, meta.clone());
        installed.insert(id, InstalledCapsule {
            metadata: meta,
            install_timestamp: crate::time::timestamp_millis(),
            code_hash: id,
            active: AtomicBool::new(true),
        });
    }
}
