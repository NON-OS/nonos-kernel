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

pub(super) const DHCP_MAGIC: [u8; 4] = [99, 130, 83, 99];

pub(super) mod dhcp_msg {
    pub(crate) const DISCOVER: u8 = 1;
    pub(crate) const OFFER: u8 = 2;
    pub(crate) const REQUEST: u8 = 3;
    pub(crate) const ACK: u8 = 5;
    pub(crate) const NAK: u8 = 6;
    pub(crate) const RELEASE: u8 = 7;
}

pub(super) mod dhcp_opt {
    pub(crate) const SUBNET_MASK: u8 = 1;
    pub(crate) const ROUTER: u8 = 3;
    pub(crate) const DNS: u8 = 6;
    pub(crate) const HOSTNAME: u8 = 12;
    pub(crate) const DOMAIN_NAME: u8 = 15;
    pub(crate) const BROADCAST: u8 = 28;
    pub(crate) const REQUESTED_IP: u8 = 50;
    pub(crate) const LEASE_TIME: u8 = 51;
    pub(crate) const MSG_TYPE: u8 = 53;
    pub(crate) const SERVER_ID: u8 = 54;
    pub(crate) const PARAM_REQUEST: u8 = 55;
    pub(crate) const RENEWAL_TIME: u8 = 58;
    pub(crate) const REBIND_TIME: u8 = 59;
    pub(crate) const CLIENT_ID: u8 = 61;
    pub(crate) const END: u8 = 255;
}
