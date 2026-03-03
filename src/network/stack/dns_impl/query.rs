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

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use smoltcp::{
    socket::udp::{self, PacketBuffer, PacketMetadata},
    wire::{IpAddress as SmolIpAddress, Ipv4Address as SmolIpv4Address},
};

use super::super::core::NetworkStack;
use super::super::device::now_ms;
use super::builder::build_dns_query_type;
use super::parser::{
    parse_dns_response_a, parse_dns_response_aaaa, parse_dns_response_any,
    parse_dns_response_cname, parse_dns_response_mx, parse_dns_response_ns,
    parse_dns_response_txt,
};
use crate::network::dns::{DnsRecord, DnsRecordType, MxRecord};

impl NetworkStack {
    pub fn dns_query_a(&self, hostname: &str, timeout_ms: u64) -> Result<Vec<[u8; 4]>, &'static str> {
        let query = build_dns_query_type(hostname, DnsRecordType::A);
        let response = self.dns_query_raw(&query, timeout_ms)?;
        parse_dns_response_a(&response)
    }

    pub fn dns_query_aaaa(&self, hostname: &str, timeout_ms: u64) -> Result<Vec<[u8; 16]>, &'static str> {
        let query = build_dns_query_type(hostname, DnsRecordType::AAAA);
        let response = self.dns_query_raw(&query, timeout_ms)?;
        parse_dns_response_aaaa(&response)
    }

    pub fn dns_query_cname(&self, hostname: &str, timeout_ms: u64) -> Result<Vec<String>, &'static str> {
        let query = build_dns_query_type(hostname, DnsRecordType::CNAME);
        let response = self.dns_query_raw(&query, timeout_ms)?;
        parse_dns_response_cname(&response)
    }

    pub fn dns_query_mx(&self, hostname: &str, timeout_ms: u64) -> Result<Vec<MxRecord>, &'static str> {
        let query = build_dns_query_type(hostname, DnsRecordType::MX);
        let response = self.dns_query_raw(&query, timeout_ms)?;
        parse_dns_response_mx(&response)
    }

    pub fn dns_query_txt(&self, hostname: &str, timeout_ms: u64) -> Result<Vec<String>, &'static str> {
        let query = build_dns_query_type(hostname, DnsRecordType::TXT);
        let response = self.dns_query_raw(&query, timeout_ms)?;
        parse_dns_response_txt(&response)
    }

    pub fn dns_query_ns(&self, hostname: &str, timeout_ms: u64) -> Result<Vec<String>, &'static str> {
        let query = build_dns_query_type(hostname, DnsRecordType::NS);
        let response = self.dns_query_raw(&query, timeout_ms)?;
        parse_dns_response_ns(&response)
    }

    pub fn dns_query_any(&self, hostname: &str, timeout_ms: u64) -> Result<Vec<DnsRecord>, &'static str> {
        let query = build_dns_query_type(hostname, DnsRecordType::A);
        let response = self.dns_query_raw(&query, timeout_ms)?;
        parse_dns_response_any(&response)
    }

    pub(crate) fn dns_query_raw(&self, query: &[u8], timeout_ms: u64) -> Result<Vec<u8>, &'static str> {
        let mut sockets = self.sockets.lock();
        let rx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 8], vec![0; 1536]);
        let tx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 8], vec![0; 1536]);
        let handle = sockets.add(udp::Socket::new(rx, tx));
        drop(sockets);

        let server = *self.default_dns_v4.lock();

        {
            let mut sockets = self.sockets.lock();
            let s: &mut udp::Socket = sockets.get_mut(handle);
            s.bind(0).map_err(|_| "dns bind")?;
            let dns_endpoint = smoltcp::wire::IpEndpoint::new(
                SmolIpAddress::Ipv4(SmolIpv4Address::new(server[0], server[1], server[2], server[3])), 53
            );
            let metadata = smoltcp::socket::udp::UdpMetadata::from(dns_endpoint);
            let _ = s.send_slice(query, metadata).map_err(|_| "dns send")?;
        }

        let start = now_ms();
        let timeout = timeout_ms.min(200);

        for _ in 0..100 {
            self.poll();

            {
                let mut sockets = self.sockets.lock();
                let s: &mut udp::Socket = sockets.get_mut(handle);
                if let Ok((data, _ep)) = s.recv() {
                    let response = data.to_vec();
                    sockets.remove(handle);
                    return Ok(response);
                }
            }

            if now_ms().saturating_sub(start) > timeout {
                let mut sockets = self.sockets.lock();
                sockets.remove(handle);
                return Err("dns timeout");
            }

            for _ in 0..50 { core::hint::spin_loop(); }
        }

        let mut sockets = self.sockets.lock();
        sockets.remove(handle);
        Err("dns timeout")
    }
}
