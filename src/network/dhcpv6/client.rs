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
use super::duid::{generate_duid_llt, Duid};
use super::message::{build_dhcpv6, generate_transaction_id, Dhcpv6Message, Dhcpv6MessageType};
use super::options::Dhcpv6Option;
use crate::network::ipv6::{Ipv6Address, Ipv6Cidr};
use alloc::vec;
use alloc::vec::Vec;
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dhcpv6ClientState {
    Init,
    Solicit,
    Request,
    Bound,
    Renew,
    Rebind,
}

pub struct Dhcpv6Client {
    pub state: Dhcpv6ClientState,
    pub duid: Duid,
    pub server_duid: Option<Duid>,
    pub transaction_id: u32,
    pub addresses: Vec<(Ipv6Address, u32, u32)>,
    pub dns_servers: Vec<Ipv6Address>,
    pub start_time: u64,
    pub t1: u32,
    pub t2: u32,
}

static CLIENT: Mutex<Option<Dhcpv6Client>> = Mutex::new(None);

impl Dhcpv6Client {
    pub fn new(mac: &[u8; 6]) -> Self {
        Self {
            state: Dhcpv6ClientState::Init,
            duid: generate_duid_llt(mac),
            server_duid: None,
            transaction_id: 0,
            addresses: Vec::new(),
            dns_servers: Vec::new(),
            start_time: crate::sys::clock::uptime_ms(),
            t1: 0,
            t2: 0,
        }
    }

    pub fn build_solicit(&mut self) -> Vec<u8> {
        self.transaction_id = generate_transaction_id();
        self.state = Dhcpv6ClientState::Solicit;
        let mut msg = Dhcpv6Message::new(Dhcpv6MessageType::Solicit, self.transaction_id);
        msg.add_option(Dhcpv6Option::ClientId(self.duid.clone()));
        msg.add_option(Dhcpv6Option::ElapsedTime(0));
        msg.add_option(Dhcpv6Option::OroReq(vec![23, 24]));
        msg.add_option(Dhcpv6Option::RapidCommit);
        build_dhcpv6(&msg)
    }

    pub fn build_request(&mut self, server: &Duid) -> Vec<u8> {
        self.transaction_id = generate_transaction_id();
        self.state = Dhcpv6ClientState::Request;
        self.server_duid = Some(server.clone());
        let mut msg = Dhcpv6Message::new(Dhcpv6MessageType::Request, self.transaction_id);
        msg.add_option(Dhcpv6Option::ClientId(self.duid.clone()));
        msg.add_option(Dhcpv6Option::ServerId(server.clone()));
        msg.add_option(Dhcpv6Option::ElapsedTime(self.elapsed()));
        msg.add_option(Dhcpv6Option::OroReq(vec![23, 24]));
        build_dhcpv6(&msg)
    }

    pub fn process_reply(&mut self, msg: &Dhcpv6Message) {
        if msg.transaction_id != self.transaction_id {
            return;
        }
        if let Some(Dhcpv6Option::DnsServers(servers)) =
            msg.options.iter().find(|o| matches!(o, Dhcpv6Option::DnsServers(_)))
        {
            self.dns_servers = servers.clone();
        }
        for opt in &msg.options {
            if let Dhcpv6Option::IaAddr { addr, preferred, valid } = opt {
                self.addresses.push((*addr, *preferred, *valid));
                crate::network::ipv6::routing::add_route(Ipv6Cidr::new(*addr, 128), None, 0, 0);
            }
        }
        self.state = Dhcpv6ClientState::Bound;
    }

    fn elapsed(&self) -> u16 {
        let ms = crate::sys::clock::uptime_ms().saturating_sub(self.start_time);
        ((ms / 10).min(65535)) as u16
    }
}

pub fn start_dhcpv6() -> Result<(), i32> {
    let mac = crate::network::get_mac_address().ok_or(-1)?;
    let mut client = Dhcpv6Client::new(&mac);
    let solicit = client.build_solicit();
    *CLIENT.lock() = Some(client);
    send_dhcpv6(&solicit)
}

fn send_dhcpv6(data: &[u8]) -> Result<(), i32> {
    let src = crate::network::ipv6::slaac::generate_link_local(
        &crate::network::get_mac_address().unwrap_or([0; 6]),
    );
    let dst = Ipv6Address::from_segments([0xff02, 0, 0, 0, 0, 0, 1, 2]);
    crate::network::udp::send_udp6(&src, 546, &dst, 547, data)
}

pub fn get_dhcpv6_state() -> Option<Dhcpv6ClientState> {
    CLIENT.lock().as_ref().map(|c| c.state)
}
pub fn get_dhcpv6_addresses() -> Vec<Ipv6Address> {
    CLIENT
        .lock()
        .as_ref()
        .map(|c| c.addresses.iter().map(|(a, _, _)| *a).collect())
        .unwrap_or_default()
}
pub fn get_dhcpv6_dns() -> Vec<Ipv6Address> {
    CLIENT.lock().as_ref().map(|c| c.dns_servers.clone()).unwrap_or_default()
}
