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

pub type Ipv4Addr = [u8; 4];

pub const ANY: Ipv4Addr = [0, 0, 0, 0];
pub const BROADCAST: Ipv4Addr = [0xFF, 0xFF, 0xFF, 0xFF];
pub const LOOPBACK: Ipv4Addr = [127, 0, 0, 1];

#[inline]
pub fn is_broadcast(a: &Ipv4Addr) -> bool {
    *a == BROADCAST
}

#[inline]
pub fn is_multicast(a: &Ipv4Addr) -> bool {
    a[0] & 0xF0 == 0xE0
}

#[inline]
pub fn is_loopback(a: &Ipv4Addr) -> bool {
    a[0] == 127
}

#[inline]
pub fn is_unspecified(a: &Ipv4Addr) -> bool {
    *a == ANY
}

// Apply a /N prefix to an address. `prefix > 32` saturates to 32.
pub fn mask_with_prefix(addr: &Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let bits = if prefix > 32 { 32 } else { prefix };
    let host = u32::from_be_bytes(*addr);
    let mask = if bits == 0 { 0 } else { (!0u32).wrapping_shl(32 - bits as u32) };
    (host & mask).to_be_bytes()
}

// True iff `addr` and `other` share the same /prefix subnet.
pub fn same_subnet(addr: &Ipv4Addr, other: &Ipv4Addr, prefix: u8) -> bool {
    mask_with_prefix(addr, prefix) == mask_with_prefix(other, prefix)
}
