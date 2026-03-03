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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, Ordering};

use crate::crypto::util::rng::global::random_u64;
use crate::network::dns::DnsRecordType;

static DNS_TX_ID: AtomicU16 = AtomicU16::new(0);

fn next_dns_transaction_id() -> u16 {
    let current = DNS_TX_ID.load(Ordering::Relaxed);
    if current == 0 {
        let random_base = (random_u64() & 0xFFFF) as u16;
        let base = if random_base == 0 { 0x1000 } else { random_base };
        let _ = DNS_TX_ID.compare_exchange(0, base, Ordering::SeqCst, Ordering::Relaxed);
    }
    DNS_TX_ID.fetch_add(1, Ordering::SeqCst).wrapping_add(1)
}

pub(crate) fn build_dns_query_type(name: &str, record_type: DnsRecordType) -> Vec<u8> {
    let mut out = Vec::new();
    let tx_id = next_dns_transaction_id();
    out.extend_from_slice(&tx_id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());

    for label in name.split('.') {
        let lb = label.as_bytes();
        if lb.is_empty() || lb.len() > 63 { continue; }
        out.push(lb.len() as u8);
        out.extend_from_slice(lb);
    }
    out.push(0);

    out.extend_from_slice(&(record_type as u16).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

pub(crate) fn build_dns_query(name: &str) -> Vec<u8> {
    build_dns_query_type(name, DnsRecordType::A)
}
