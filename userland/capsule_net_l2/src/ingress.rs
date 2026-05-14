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

//! L2 ingress side-effect path. Runs on every inbound frame
//! before the bytes leave the capsule. The only stateful effect
//! today is ARP cache learning + reply emission; upstream IP /
//! IPv6 dispatch happens at the caller because it owns the
//! protocol-class routing decision.

use crate::arp::{on_inbound as arp_on_inbound, Iface};
use crate::ethernet::{payload_of, EthHeader, ETHERTYPE_ARP};
use crate::nic_client::send_frame as nic_send;
use crate::state::STATE;

pub fn observe(frame: &[u8]) {
    let Some(header) = EthHeader::parse(frame) else {
        return;
    };
    if header.ethertype != ETHERTYPE_ARP {
        return;
    }
    let Some(payload) = payload_of(frame) else {
        return;
    };
    let iface = Iface { mac: *STATE.mac.lock(), ipv4: *STATE.ipv4.lock() };
    let reply = {
        let mut cache = STATE.arp.lock();
        arp_on_inbound(&iface, &mut cache, payload)
    };
    if let Some(r) = reply {
        let nic = STATE.nic_port();
        if nic != 0 {
            let _ = nic_send(nic, &r.bytes);
        }
    }
}
