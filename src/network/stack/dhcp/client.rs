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

use alloc::vec;
use smoltcp::{
    socket::udp::{self, PacketBuffer, PacketMetadata},
    wire::{IpAddress as SmolIpAddress, Ipv4Address as SmolIpv4Address},
};

use super::constants::dhcp_msg;
use super::message::{build_dhcp_message, send_dhcp_broadcast, parse_dhcp_response, count_subnet_bits};
use super::types::{DhcpState, DhcpLeaseInfo, DHCP_CLIENT};
use crate::network::stack::core::NetworkStack;
use crate::network::stack::device::{DEVICE_SLOT, DEFAULT_MAC, now_ms};
use crate::network::stack::types::DhcpLease;

impl NetworkStack {
    pub fn request_dhcp(&self) -> Result<DhcpLease, &'static str> {
        let mac = DEVICE_SLOT.get().map(|d| d.mac()).unwrap_or(DEFAULT_MAC);

        let mut sockets = self.sockets.lock();
        let rx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 8], vec![0; 2048]);
        let tx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 8], vec![0; 2048]);
        let handle = sockets.add(udp::Socket::new(rx, tx));
        drop(sockets);

        {
            let mut sockets = self.sockets.lock();
            let s: &mut udp::Socket = sockets.get_mut(handle);
            s.bind(68).map_err(|_| "dhcp bind failed")?;
        }

        let mut client = DHCP_CLIENT.lock();
        client.new_xid();
        client.state = DhcpState::Init;

        let discover = build_dhcp_message(&mac, client.xid, dhcp_msg::DISCOVER, None, None);
        {
            let mut sockets = self.sockets.lock();
            let s: &mut udp::Socket = sockets.get_mut(handle);
            send_dhcp_broadcast(s, &discover)?;
        }
        client.state = DhcpState::Selecting;
        drop(client);

        let offer = self.wait_for_dhcp_response(handle, dhcp_msg::OFFER, 5000)?;

        let mut client = DHCP_CLIENT.lock();
        let requested_ip = offer.ip;
        let server_ip = offer.server_ip;

        let request = build_dhcp_message(
            &mac,
            client.xid,
            dhcp_msg::REQUEST,
            Some(requested_ip),
            Some(server_ip),
        );
        {
            let mut sockets = self.sockets.lock();
            let s: &mut udp::Socket = sockets.get_mut(handle);
            send_dhcp_broadcast(s, &request)?;
        }
        client.state = DhcpState::Requesting;
        drop(client);

        let ack = self.wait_for_dhcp_response(handle, dhcp_msg::ACK, 5000)?;

        let subnet_bits = count_subnet_bits(ack.subnet_mask);
        self.set_ipv4_config(ack.ip, subnet_bits, Some(ack.gateway));
        self.set_default_dns_v4(ack.dns_primary);

        let mut client = DHCP_CLIENT.lock();
        client.state = DhcpState::Bound;
        client.lease = Some(ack.clone());
        drop(client);

        let mut sockets = self.sockets.lock();
        sockets.remove(handle);

        crate::log::info!(
            "DHCP: Acquired lease {}.{}.{}.{}/{} gateway {}.{}.{}.{} lease {}s",
            ack.ip[0], ack.ip[1], ack.ip[2], ack.ip[3],
            subnet_bits,
            ack.gateway[0], ack.gateway[1], ack.gateway[2], ack.gateway[3],
            ack.lease_time
        );

        Ok(DhcpLease {
            ip: ack.ip,
            gateway: ack.gateway,
            dns: ack.dns_primary,
            lease_time: ack.lease_time,
        })
    }

    fn wait_for_dhcp_response(
        &self,
        handle: smoltcp::iface::SocketHandle,
        expected_type: u8,
        timeout_ms: u64,
    ) -> Result<DhcpLeaseInfo, &'static str> {
        let start = now_ms();
        let client = DHCP_CLIENT.lock();
        let expected_xid = client.xid;
        drop(client);

        loop {
            {
                let mut sockets = self.sockets.lock();
                let s: &mut udp::Socket = sockets.get_mut(handle);
                if let Ok((data, _ep)) = s.recv() {
                    if let Some((msg_type, lease)) = parse_dhcp_response(data) {
                        let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                        if xid == expected_xid {
                            if msg_type == expected_type {
                                return Ok(lease);
                            } else if msg_type == dhcp_msg::NAK {
                                return Err("dhcp nak received");
                            }
                        }
                    }
                }
            }

            self.poll();

            if now_ms().saturating_sub(start) > timeout_ms {
                return Err("dhcp timeout");
            }

            crate::time::yield_now();
        }
    }

    pub fn renew_dhcp(&self) -> Result<(), &'static str> {
        let client = DHCP_CLIENT.lock();
        let lease = client.lease.as_ref().ok_or("no lease to renew")?;
        let current_ip = lease.ip;
        let server_ip = lease.server_ip;
        drop(client);

        let mac = DEVICE_SLOT.get().map(|d| d.mac()).unwrap_or(DEFAULT_MAC);

        let mut sockets = self.sockets.lock();
        let rx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 4], vec![0; 1500]);
        let tx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 4], vec![0; 1500]);
        let handle = sockets.add(udp::Socket::new(rx, tx));
        drop(sockets);

        {
            let mut sockets = self.sockets.lock();
            let s: &mut udp::Socket = sockets.get_mut(handle);
            s.bind(68).map_err(|_| "dhcp bind failed")?;
        }

        let mut client = DHCP_CLIENT.lock();
        client.new_xid();
        client.state = DhcpState::Renewing;

        let request = build_dhcp_message(
            &mac,
            client.xid,
            dhcp_msg::REQUEST,
            Some(current_ip),
            None,
        );

        {
            let mut sockets = self.sockets.lock();
            let s: &mut udp::Socket = sockets.get_mut(handle);
            let endpoint = smoltcp::wire::IpEndpoint::new(
                SmolIpAddress::Ipv4(SmolIpv4Address::from_bytes(&server_ip)),
                67,
            );
            let metadata = smoltcp::socket::udp::UdpMetadata::from(endpoint);
            s.send_slice(&request, metadata).map_err(|_| "dhcp send failed")?;
        }
        drop(client);

        match self.wait_for_dhcp_response(handle, dhcp_msg::ACK, 5000) {
            Ok(ack) => {
                let mut client = DHCP_CLIENT.lock();
                client.state = DhcpState::Bound;
                client.lease = Some(ack.clone());

                crate::log::info!("DHCP: Lease renewed, expires in {}s", ack.lease_time);
            }
            Err(e) => {
                let mut client = DHCP_CLIENT.lock();
                client.state = DhcpState::Rebinding;
                let mut sockets = self.sockets.lock();
                sockets.remove(handle);
                return Err(e);
            }
        }

        let mut sockets = self.sockets.lock();
        sockets.remove(handle);
        Ok(())
    }

    pub fn release_dhcp(&self) -> Result<(), &'static str> {
        let client = DHCP_CLIENT.lock();
        let lease = client.lease.as_ref().ok_or("no lease to release")?;
        let current_ip = lease.ip;
        let server_ip = lease.server_ip;
        drop(client);

        let mac = DEVICE_SLOT.get().map(|d| d.mac()).unwrap_or(DEFAULT_MAC);

        let mut sockets = self.sockets.lock();
        let rx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 2], vec![0; 512]);
        let tx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 2], vec![0; 512]);
        let handle = sockets.add(udp::Socket::new(rx, tx));
        drop(sockets);

        {
            let mut sockets = self.sockets.lock();
            let s: &mut udp::Socket = sockets.get_mut(handle);
            s.bind(68).map_err(|_| "dhcp bind failed")?;
        }

        let mut client = DHCP_CLIENT.lock();
        client.new_xid();

        let release = build_dhcp_message(
            &mac,
            client.xid,
            dhcp_msg::RELEASE,
            Some(current_ip),
            Some(server_ip),
        );

        {
            let mut sockets = self.sockets.lock();
            let s: &mut udp::Socket = sockets.get_mut(handle);
            let endpoint = smoltcp::wire::IpEndpoint::new(
                SmolIpAddress::Ipv4(SmolIpv4Address::from_bytes(&server_ip)),
                67,
            );
            let metadata = smoltcp::socket::udp::UdpMetadata::from(endpoint);
            let _ = s.send_slice(&release, metadata);
        }

        client.state = DhcpState::Init;
        client.lease = None;
        drop(client);

        let mut sockets = self.sockets.lock();
        sockets.remove(handle);

        crate::log::info!("DHCP: Lease released");
        Ok(())
    }

    pub fn dhcp_maintenance(&self) {
        let client = DHCP_CLIENT.lock();
        let needs_renewal = client.needs_renewal();
        let needs_rebinding = client.needs_rebinding();
        let lease_expired = client.lease_expired();
        drop(client);

        if lease_expired {
            crate::log::info!("DHCP: Lease expired, requesting new lease");
            let _ = self.request_dhcp();
        } else if needs_rebinding {
            crate::log::info!("DHCP: T2 expired, rebinding");
            let _ = self.request_dhcp();
        } else if needs_renewal {
            crate::log::info!("DHCP: T1 expired, renewing");
            if self.renew_dhcp().is_err() {
                let _ = self.request_dhcp();
            }
        }
    }
}
