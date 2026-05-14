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

pub type MacAddress = [u8; 6];

pub const MAC_BROADCAST: MacAddress = [0xFF; 6];
pub const MAC_ZERO: MacAddress = [0; 6];

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

#[inline]
pub fn mac_is_broadcast(mac: &MacAddress) -> bool {
    *mac == MAC_BROADCAST
}

#[inline]
pub fn mac_is_multicast(mac: &MacAddress) -> bool {
    mac[0] & 0x01 != 0
}

#[inline]
pub fn mac_is_zero(mac: &MacAddress) -> bool {
    *mac == MAC_ZERO
}
