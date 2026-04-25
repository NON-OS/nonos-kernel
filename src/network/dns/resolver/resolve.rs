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

use super::super::cache::{DNS_CACHE, DNS_STATS};
use super::super::types::{
    DnsCacheEntry, DnsQueryRecord, PendingQuery, DEFAULT_TIMEOUT_MS, MAX_CNAME_DEPTH,
    MAX_QUERY_CACHE,
};
use crate::network::ip::IpAddress;
use alloc::string::String;
use alloc::vec::Vec;

pub fn resolve(hostname: &str) -> Result<Vec<IpAddress>, &'static str> {
    DNS_STATS.inc_total();
    {
        let cache = DNS_CACHE.lock();
        let now = crate::time::timestamp_millis();
        for entry in cache.entries.iter() {
            if entry.hostname == hostname && now < entry.timestamp_ms + entry.ttl_ms {
                DNS_STATS.inc_cached();
                return Ok(entry.addresses.iter().map(|&a| IpAddress::V4(a)).collect());
            }
        }
    }
    let ns = crate::network::get_network_stack().ok_or("network not initialized")?;
    {
        let mut cache = DNS_CACHE.lock();
        cache.pending_queries.push(PendingQuery {
            hostname: String::from(hostname),
            start_ms: crate::time::timestamp_millis(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
        });
    }
    let result = resolve_with_cname_follow(&ns, hostname);
    {
        let mut cache = DNS_CACHE.lock();
        cache.pending_queries.retain(|q| q.hostname != hostname);
    }
    match result {
        Ok((addrs, ttl_seconds)) => {
            let now = crate::time::timestamp_millis();
            let ttl_ms = (ttl_seconds as u64).saturating_mul(1000);
            let mut cache = DNS_CACHE.lock();
            cache.query_history.push_back(DnsQueryRecord {
                hostname: String::from(hostname),
                timestamp_ms: now,
                success: true,
            });
            if cache.query_history.len() > MAX_QUERY_CACHE {
                cache.query_history.pop_front();
            }
            cache.entries.retain(|e| e.hostname != hostname);
            cache.entries.push_back(DnsCacheEntry {
                hostname: String::from(hostname),
                addresses: addrs.clone(),
                timestamp_ms: now,
                ttl_ms,
            });
            if cache.entries.len() > MAX_QUERY_CACHE {
                cache.entries.pop_front();
            }
            Ok(addrs.into_iter().map(IpAddress::V4).collect())
        }
        Err(e) => {
            DNS_STATS.inc_failed();
            let mut cache = DNS_CACHE.lock();
            cache.query_history.push_back(DnsQueryRecord {
                hostname: String::from(hostname),
                timestamp_ms: crate::time::timestamp_millis(),
                success: false,
            });
            if cache.query_history.len() > MAX_QUERY_CACHE {
                cache.query_history.pop_front();
            }
            Err(e)
        }
    }
}

fn resolve_with_cname_follow(
    ns: &crate::network::stack::NetworkStack,
    hostname: &str,
) -> Result<(Vec<[u8; 4]>, u32), &'static str> {
    let mut current = String::from(hostname);
    let mut min_ttl = u32::MAX;
    for _ in 0..MAX_CNAME_DEPTH {
        let query_result = ns.dns_query_a_with_ttl(&current, DEFAULT_TIMEOUT_MS);
        let (addrs, ttl, mut cnames) = match query_result {
            Ok(v) => v,
            Err(_) => {
                let direct = ns.dns_query_a(&current, DEFAULT_TIMEOUT_MS).unwrap_or_default();
                if !direct.is_empty() {
                    if min_ttl == u32::MAX {
                        min_ttl = 300;
                    }
                    return Ok((direct, min_ttl));
                }
                let cname_fallback =
                    ns.dns_query_cname(&current, DEFAULT_TIMEOUT_MS).unwrap_or_default();
                if let Some(next) = cname_fallback.into_iter().next() {
                    current = next;
                    continue;
                }
                return Err("dns query failed");
            }
        };
        if ttl < min_ttl {
            min_ttl = ttl;
        }
        if !addrs.is_empty() {
            return Ok((addrs, min_ttl));
        }
        if cnames.is_empty() {
            cnames = ns.dns_query_cname(&current, DEFAULT_TIMEOUT_MS).unwrap_or_default();
        }
        if let Some(cname) = cnames.into_iter().next() {
            current = cname;
        } else {
            let direct = ns.dns_query_a(&current, DEFAULT_TIMEOUT_MS).unwrap_or_default();
            if !direct.is_empty() {
                if min_ttl == u32::MAX {
                    min_ttl = 300;
                }
                return Ok((direct, min_ttl));
            }
            break;
        }
    }
    Err("no A record found")
}
