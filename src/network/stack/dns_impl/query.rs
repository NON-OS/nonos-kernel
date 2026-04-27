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
    parse_dns_response_a, parse_dns_response_a_with_ttl, parse_dns_response_aaaa,
    parse_dns_response_aaaa_with_ttl, parse_dns_response_any, parse_dns_response_cname,
    parse_dns_response_mx, parse_dns_response_ns, parse_dns_response_txt,
};
use crate::network::dns::{DnsRecord, DnsRecordType, MxRecord};

#[inline]
fn is_valid_dns_response(packet: &[u8], expected_txid: u16) -> bool {
    if packet.len() < 12 {
        return false;
    }

    let txid = u16::from_be_bytes([packet[0], packet[1]]);
    if txid != expected_txid {
        return false;
    }

    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let is_response = (flags & 0x8000) != 0;
    if !is_response {
        return false;
    }

    let rcode = flags & 0x000F;
    rcode == 0
}

impl NetworkStack {
    pub fn dns_query_a(
        &self,
        hostname: &str,
        timeout_ms: u64,
    ) -> Result<Vec<[u8; 4]>, &'static str> {
        let query = build_dns_query_type(hostname, DnsRecordType::A);
        let response = self.dns_query_raw(&query, timeout_ms)?;
        parse_dns_response_a(&response)
    }

    pub fn dns_query_a_with_ttl(
        &self,
        hostname: &str,
        timeout_ms: u64,
    ) -> Result<(Vec<[u8; 4]>, u32, Vec<String>), &'static str> {
        let query = build_dns_query_type(hostname, DnsRecordType::A);
        let response = self.dns_query_raw(&query, timeout_ms)?;
        parse_dns_response_a_with_ttl(&response)
    }

    pub fn dns_query_aaaa_with_ttl(
        &self,
        hostname: &str,
        timeout_ms: u64,
    ) -> Result<(Vec<[u8; 16]>, u32), &'static str> {
        let query = build_dns_query_type(hostname, DnsRecordType::AAAA);
        let response = self.dns_query_raw(&query, timeout_ms)?;
        parse_dns_response_aaaa_with_ttl(&response)
    }

    pub fn dns_query_aaaa(
        &self,
        hostname: &str,
        timeout_ms: u64,
    ) -> Result<Vec<[u8; 16]>, &'static str> {
        let query = build_dns_query_type(hostname, DnsRecordType::AAAA);
        let response = self.dns_query_raw(&query, timeout_ms)?;
        parse_dns_response_aaaa(&response)
    }

    pub fn dns_query_cname(
        &self,
        hostname: &str,
        timeout_ms: u64,
    ) -> Result<Vec<String>, &'static str> {
        let query = build_dns_query_type(hostname, DnsRecordType::CNAME);
        let response = self.dns_query_raw(&query, timeout_ms)?;
        parse_dns_response_cname(&response)
    }

    pub fn dns_query_mx(
        &self,
        hostname: &str,
        timeout_ms: u64,
    ) -> Result<Vec<MxRecord>, &'static str> {
        let query = build_dns_query_type(hostname, DnsRecordType::MX);
        let response = self.dns_query_raw(&query, timeout_ms)?;
        parse_dns_response_mx(&response)
    }

    pub fn dns_query_txt(
        &self,
        hostname: &str,
        timeout_ms: u64,
    ) -> Result<Vec<String>, &'static str> {
        let query = build_dns_query_type(hostname, DnsRecordType::TXT);
        let response = self.dns_query_raw(&query, timeout_ms)?;
        parse_dns_response_txt(&response)
    }

    pub fn dns_query_ns(
        &self,
        hostname: &str,
        timeout_ms: u64,
    ) -> Result<Vec<String>, &'static str> {
        let query = build_dns_query_type(hostname, DnsRecordType::NS);
        let response = self.dns_query_raw(&query, timeout_ms)?;
        parse_dns_response_ns(&response)
    }

    pub fn dns_query_any(
        &self,
        hostname: &str,
        timeout_ms: u64,
    ) -> Result<Vec<DnsRecord>, &'static str> {
        let query = build_dns_query_type(hostname, DnsRecordType::A);
        let response = self.dns_query_raw(&query, timeout_ms)?;
        parse_dns_response_any(&response)
    }

    pub(crate) fn dns_query_raw(
        &self,
        query: &[u8],
        timeout_ms: u64,
    ) -> Result<Vec<u8>, &'static str> {
        let configured = *self.default_dns_v4.lock();
        let timeout = timeout_ms.max(2000);
        let start_total = now_ms();
        let expected_txid =
            if query.len() >= 2 { u16::from_be_bytes([query[0], query[1]]) } else { 0 };
        let mut total_spin_count: u32 = 0;
        // Hard fail-safe independent of timer progression.
        const MAX_TOTAL_SPINS: u32 = 200_000;
        const MAX_ATTEMPT_SPINS: u32 = 100_000;

        let mut servers = [[0u8; 4]; 2];
        let mut server_count = 0usize;

        // Prefer QEMU usernet DNS first, then configured server.
        for candidate in [[10, 0, 2, 3], configured] {
            if candidate == [0, 0, 0, 0] {
                continue;
            }

            let mut duplicate = false;
            for existing in servers.iter().take(server_count) {
                if *existing == candidate {
                    duplicate = true;
                    break;
                }
            }

            if !duplicate {
                servers[server_count] = candidate;
                server_count += 1;
                if server_count >= servers.len() {
                    break;
                }
            }
        }

        for (server_idx, server) in servers.iter().take(server_count).enumerate() {
            for attempt in 0..1usize {
                if now_ms().saturating_sub(start_total) >= timeout {
                    return Err("dns timeout");
                }
                if total_spin_count >= MAX_TOTAL_SPINS {
                    return Err("dns timeout");
                }

                let mut sockets = self.sockets.lock();
                let rx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 8], vec![0; 1536]);
                let tx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 8], vec![0; 1536]);
                let handle = sockets.add(udp::Socket::new(rx, tx));

                let sent = {
                    let s: &mut udp::Socket = sockets.get_mut(handle);
                    let offset = ((server_idx as u16) * 37).wrapping_add((attempt as u16) * 13);
                    let ephemeral_port = 49152 + (((now_ms() as u16).wrapping_add(offset)) % 16383);
                    if s.bind(ephemeral_port).is_err() {
                        false
                    } else {
                        let dns_endpoint = smoltcp::wire::IpEndpoint::new(
                            SmolIpAddress::Ipv4(SmolIpv4Address::new(
                                server[0], server[1], server[2], server[3],
                            )),
                            53,
                        );
                        let metadata = smoltcp::socket::udp::UdpMetadata::from(dns_endpoint);
                        s.send_slice(query, metadata).is_ok()
                    }
                };

                drop(sockets);

                if !sent {
                    let mut sockets = self.sockets.lock();
                    sockets.remove(handle);
                    continue;
                }

                let mut attempt_spin_count: u32 = 0;
                loop {
                    total_spin_count = total_spin_count.saturating_add(1);
                    attempt_spin_count = attempt_spin_count.saturating_add(1);

                    self.poll();

                    let mut maybe_response = None;
                    {
                        let mut sockets = self.sockets.lock();
                        let s: &mut udp::Socket = sockets.get_mut(handle);
                        if let Ok((data, ep)) = s.recv() {
                            let from_expected_server = ep.endpoint.port == 53
                                && ep.endpoint.addr
                                    == SmolIpAddress::Ipv4(SmolIpv4Address::new(
                                        server[0], server[1], server[2], server[3],
                                    ));

                            if from_expected_server && is_valid_dns_response(data, expected_txid) {
                                crate::sys::serial::println(b"[DNS] accepted response");
                                maybe_response = Some(data.to_vec());
                            } else {
                                crate::sys::serial::println(b"[DNS] ignored non-matching response");
                            }
                        }
                    }

                    if let Some(response) = maybe_response {
                        let mut sockets = self.sockets.lock();
                        sockets.remove(handle);
                        return Ok(response);
                    }

                    // Evaluate timeout after poll/recv so a near-deadline packet is not dropped.
                    if now_ms().saturating_sub(start_total) >= timeout {
                        // Final short drain to capture packets that landed right at the deadline.
                        let mut recovered = None;
                        for _ in 0..8 {
                            self.poll();
                            {
                                let mut sockets = self.sockets.lock();
                                let s: &mut udp::Socket = sockets.get_mut(handle);
                                if let Ok((data, ep)) = s.recv() {
                                    let from_expected_server = ep.endpoint.port == 53
                                        && ep.endpoint.addr
                                            == SmolIpAddress::Ipv4(SmolIpv4Address::new(
                                                server[0], server[1], server[2], server[3],
                                            ));

                                    if from_expected_server
                                        && is_valid_dns_response(data, expected_txid)
                                    {
                                        recovered = Some(data.to_vec());
                                    }
                                }
                            }

                            if recovered.is_some() {
                                break;
                            }

                            crate::time::yield_now();
                        }

                        if let Some(response) = recovered {
                            let mut sockets = self.sockets.lock();
                            sockets.remove(handle);
                            return Ok(response);
                        }

                        let mut sockets = self.sockets.lock();
                        sockets.remove(handle);
                        break;
                    }

                    if total_spin_count >= MAX_TOTAL_SPINS
                        || attempt_spin_count >= MAX_ATTEMPT_SPINS
                    {
                        let mut sockets = self.sockets.lock();
                        sockets.remove(handle);
                        break;
                    }

                    crate::time::yield_now();
                }
            }
        }

        Err("dns timeout")
    }
}
