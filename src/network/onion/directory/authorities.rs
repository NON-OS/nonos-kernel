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

//! Default directory authority definitions for the Anyone network (anyone.io)
//!
//! Anyone is a decentralized communication network built on anonymity, privacy,
//! and global accessibility. It is a fork of Tor with its own directory authorities.

use alloc::{vec, vec::Vec};
use super::types::DirectoryAuthority;
use super::encoding::hex_to_vec;

/// Default OR port for Anyone relays
pub(super) const ANYONE_OR_PORT: u16 = 9201;

/// Default directory port for Anyone authorities
pub(super) const ANYONE_DIR_PORT: u16 = 9230;

/// Returns the default set of Anyone directory authorities
/// These are the official Anyone network directory authorities.
pub(super) fn default_authorities() -> Vec<DirectoryAuthority> {
    vec![
        // European authorities
        DirectoryAuthority {
            nickname: "ATORDAeuclive".into(),
            ed25519_identity: None,
            identity_fingerprint: hex_to_vec("88F29CB5FE86A688E31990A3B20BD562D0C089E1").unwrap_or_default(),
            address: [49, 13, 145, 234],  // 49.13.145.234
            dir_port: ANYONE_DIR_PORT,
            or_port: ANYONE_OR_PORT,
        },
        // US East authorities
        DirectoryAuthority {
            nickname: "ATORDAuselive".into(),
            ed25519_identity: None,
            identity_fingerprint: hex_to_vec("9572A9D4141A2AFC43C416E978D805E7C98B3B25").unwrap_or_default(),
            address: [5, 161, 108, 187],  // 5.161.108.187
            dir_port: ANYONE_DIR_PORT,
            or_port: ANYONE_OR_PORT,
        },
        // US West authorities
        DirectoryAuthority {
            nickname: "ATORDAuswlive".into(),
            ed25519_identity: None,
            identity_fingerprint: hex_to_vec("FFBFD3D2E92EEAA9162335FF8DF259CC62713784").unwrap_or_default(),
            address: [5, 78, 90, 106],  // 5.78.90.106
            dir_port: ANYONE_DIR_PORT,
            or_port: ANYONE_OR_PORT,
        },
        // Ashburn datacenter
        DirectoryAuthority {
            nickname: "AnyoneAshLive".into(),
            ed25519_identity: None,
            identity_fingerprint: hex_to_vec("6CE85CF74AB78E4D350E0418234B97F47AB32A20").unwrap_or_default(),
            address: [5, 161, 228, 187],  // 5.161.228.187
            dir_port: ANYONE_DIR_PORT,
            or_port: ANYONE_OR_PORT,
        },
        // Hillsboro datacenter
        DirectoryAuthority {
            nickname: "AnyoneHilLive".into(),
            ed25519_identity: None,
            identity_fingerprint: hex_to_vec("39C78145CFDF464E624626D4F78A315387132082").unwrap_or_default(),
            address: [5, 78, 94, 15],  // 5.78.94.15
            dir_port: ANYONE_DIR_PORT,
            or_port: ANYONE_OR_PORT,
        },
        // Helsinki datacenter
        DirectoryAuthority {
            nickname: "AnyoneHelLive".into(),
            ed25519_identity: None,
            identity_fingerprint: hex_to_vec("5F18C895685A4207E0778FEB2A9CE4C90DABE7A6").unwrap_or_default(),
            address: [95, 216, 32, 105],  // 95.216.32.105
            dir_port: ANYONE_DIR_PORT,
            or_port: ANYONE_OR_PORT,
        },
        // Falkenstein datacenter
        DirectoryAuthority {
            nickname: "AnyoneFalLive".into(),
            ed25519_identity: None,
            identity_fingerprint: hex_to_vec("271F7D1592BF37AEB67BF48164928720EF9D0648").unwrap_or_default(),
            address: [176, 9, 29, 53],  // 176.9.29.53
            dir_port: ANYONE_DIR_PORT,
            or_port: ANYONE_OR_PORT,
        },
    ]
}

