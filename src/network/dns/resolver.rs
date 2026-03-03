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
use alloc::vec::Vec;

use crate::network::ip::IpAddress;

use super::types::{
    DnsCacheEntry, DnsQueryRecord, PendingQuery, MxRecord, DnsRecord,
    MAX_QUERY_CACHE, DEFAULT_TTL_MS, DEFAULT_TIMEOUT_MS,
};
use super::cache::{DNS_CACHE, DNS_STATS};

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

    if let Some(ns) = crate::network::get_network_stack() {
        {
            let mut cache = DNS_CACHE.lock();
            cache.pending_queries.push(PendingQuery {
                hostname: String::from(hostname),
                start_ms: crate::time::timestamp_millis(),
                timeout_ms: DEFAULT_TIMEOUT_MS,
            });
        }

        let result = ns.dns_query_a(hostname, 300);

        {
            let mut cache = DNS_CACHE.lock();
            cache.pending_queries.retain(|q| q.hostname != hostname);
        }

        match result {
            Ok(addrs) => {
                let now = crate::time::timestamp_millis();
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
                    ttl_ms: DEFAULT_TTL_MS,
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
    } else {
        DNS_STATS.inc_failed();
        Err("network not initialized")
    }
}

pub fn resolve_v4(hostname: &str) -> Result<[u8; 4], &'static str> {
    let v = resolve(hostname)?;
    for a in v {
        if let IpAddress::V4(v4) = a {
            return Ok(v4);
        }
    }
    Err("no A record")
}

pub fn resolve_v6(hostname: &str) -> Result<Vec<[u8; 16]>, &'static str> {
    DNS_STATS.inc_total();

    if let Some(ns) = crate::network::get_network_stack() {
        match ns.dns_query_aaaa(hostname, 300) {
            Ok(addrs) => {
                record_success(hostname);
                Ok(addrs)
            }
            Err(e) => {
                record_failure(hostname);
                Err(e)
            }
        }
    } else {
        DNS_STATS.inc_failed();
        Err("network not initialized")
    }
}

pub fn resolve_cname(hostname: &str) -> Result<Vec<String>, &'static str> {
    DNS_STATS.inc_total();

    if let Some(ns) = crate::network::get_network_stack() {
        match ns.dns_query_cname(hostname, 300) {
            Ok(names) => {
                record_success(hostname);
                Ok(names)
            }
            Err(e) => {
                record_failure(hostname);
                Err(e)
            }
        }
    } else {
        DNS_STATS.inc_failed();
        Err("network not initialized")
    }
}

pub fn resolve_mx(hostname: &str) -> Result<Vec<MxRecord>, &'static str> {
    DNS_STATS.inc_total();

    if let Some(ns) = crate::network::get_network_stack() {
        match ns.dns_query_mx(hostname, 300) {
            Ok(records) => {
                record_success(hostname);
                Ok(records)
            }
            Err(e) => {
                record_failure(hostname);
                Err(e)
            }
        }
    } else {
        DNS_STATS.inc_failed();
        Err("network not initialized")
    }
}

pub fn resolve_txt(hostname: &str) -> Result<Vec<String>, &'static str> {
    DNS_STATS.inc_total();

    if let Some(ns) = crate::network::get_network_stack() {
        match ns.dns_query_txt(hostname, 300) {
            Ok(records) => {
                record_success(hostname);
                Ok(records)
            }
            Err(e) => {
                record_failure(hostname);
                Err(e)
            }
        }
    } else {
        DNS_STATS.inc_failed();
        Err("network not initialized")
    }
}

pub fn resolve_ns(hostname: &str) -> Result<Vec<String>, &'static str> {
    DNS_STATS.inc_total();

    if let Some(ns) = crate::network::get_network_stack() {
        match ns.dns_query_ns(hostname, 300) {
            Ok(records) => {
                record_success(hostname);
                Ok(records)
            }
            Err(e) => {
                record_failure(hostname);
                Err(e)
            }
        }
    } else {
        DNS_STATS.inc_failed();
        Err("network not initialized")
    }
}

pub fn resolve_any(hostname: &str) -> Result<Vec<DnsRecord>, &'static str> {
    DNS_STATS.inc_total();

    if let Some(ns) = crate::network::get_network_stack() {
        match ns.dns_query_any(hostname, 300) {
            Ok(records) => {
                record_success(hostname);
                Ok(records)
            }
            Err(e) => {
                record_failure(hostname);
                Err(e)
            }
        }
    } else {
        DNS_STATS.inc_failed();
        Err("network not initialized")
    }
}

fn record_success(hostname: &str) {
    let now = crate::time::timestamp_millis();
    let mut cache = DNS_CACHE.lock();
    cache.query_history.push_back(DnsQueryRecord {
        hostname: String::from(hostname),
        timestamp_ms: now,
        success: true,
    });
    if cache.query_history.len() > MAX_QUERY_CACHE {
        cache.query_history.pop_front();
    }
}

fn record_failure(hostname: &str) {
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
}

pub fn check_dns_timeouts() {
    let now = crate::time::timestamp_millis();
    let mut cache = DNS_CACHE.lock();

    cache.entries.retain(|e| now < e.timestamp_ms + e.ttl_ms);

    let timed_out: Vec<_> = cache
        .pending_queries
        .iter()
        .filter(|q| now > q.start_ms + q.timeout_ms)
        .map(|q| q.hostname.clone())
        .collect();

    for hostname in timed_out {
        cache.pending_queries.retain(|q| q.hostname != hostname);
        cache.query_history.push_back(DnsQueryRecord {
            hostname,
            timestamp_ms: now,
            success: false,
        });
        DNS_STATS.inc_failed();
    }
}

pub fn get_recent_queries() -> Vec<String> {
    let cache = DNS_CACHE.lock();
    cache
        .query_history
        .iter()
        .rev()
        .take(20)
        .map(|q| q.hostname.clone())
        .collect()
}

pub fn get_stats() -> (u64, u64, u64) {
    DNS_STATS.get()
}

pub fn clear_cache() {
    let mut cache = DNS_CACHE.lock();
    cache.entries.clear();
}

pub fn init() -> Result<(), &'static str> {
    crate::log::info!("DNS resolver initialized");
    Ok(())
}
