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

//! Cached lease parameters. `prefix` is the subnet mask converted
//! to bit count (24 for 255.255.255.0); `lease_seconds` is the
//! server-supplied lifetime — the capsule does not implement
//! lease-expiry timers on its own, the caller drives renewal
//! through `OP_LEASE_RENEW`.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lease {
    pub ipv4: [u8; 4],
    pub prefix: u8,
    pub gateway: [u8; 4],
    pub server_id: [u8; 4],
    pub dns: [u8; 4],
    pub lease_seconds: u32,
}

impl Lease {
    pub const fn empty() -> Self {
        Self {
            ipv4: [0; 4],
            prefix: 0,
            gateway: [0; 4],
            server_id: [0; 4],
            dns: [0; 4],
            lease_seconds: 0,
        }
    }
}
