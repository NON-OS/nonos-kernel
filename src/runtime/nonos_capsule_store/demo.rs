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

use alloc::string::String;

use crate::crypto::hash::blake3_hash;

use super::constants::MICRO_FEE_NOX;
use super::types::{CapsuleCategory, CapsuleMetadata};
use super::state::CAPSULE_STORE;

pub fn add_demo_capsules() {
    let lock = CAPSULE_STORE.lock();
    if let Some(store) = lock.as_ref() {
        let demos = [
            ("tor-browser", "11.0.0", "Anonymous web browsing via Tor", CapsuleCategory::Privacy, MICRO_FEE_NOX),
            ("signal", "6.0.0", "End-to-end encrypted messaging", CapsuleCategory::Communication, MICRO_FEE_NOX),
            ("bitcoin-wallet", "0.21.0", "Bitcoin wallet with hardware key support", CapsuleCategory::Finance, MICRO_FEE_NOX * 2),
            ("file-vault", "1.0.0", "Encrypted file storage", CapsuleCategory::Security, MICRO_FEE_NOX),
            ("code-editor", "2.0.0", "Lightweight code editor", CapsuleCategory::Development, MICRO_FEE_NOX),
            ("media-player", "1.5.0", "Privacy-focused media player", CapsuleCategory::Media, MICRO_FEE_NOX / 2),
            ("password-manager", "3.0.0", "Secure password storage", CapsuleCategory::Security, MICRO_FEE_NOX),
            ("vpn-client", "1.0.0", "WireGuard VPN client", CapsuleCategory::Network, MICRO_FEE_NOX),
        ];

        let mut available = store.available.write();

        for (name, version, desc, category, fee) in demos {
            let id = blake3_hash(name.as_bytes());
            let meta = CapsuleMetadata {
                id,
                name: String::from(name),
                version: String::from(version),
                description: String::from(desc),
                author: String::from("NONOS Community"),
                category,
                size_bytes: 1024 * 1024,
                nox_fee: fee,
                signature: [0u8; 64],
                ed25519_pubkey: [0u8; 32],
                dilithium_signature: None,
            };
            available.insert(id, meta);
        }
    }
}
