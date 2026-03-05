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

//! DNS resolver with caching support
//!
//! Supports the following record types:
//! - A (IPv4 address)
//! - AAAA (IPv6 address)
//! - CNAME (Canonical name)
//! - MX (Mail exchange)
//! - TXT (Text records)
//! - NS (Nameserver)
//! - PTR (Pointer)
//! - SRV (Service locator)

mod types;
mod cache;
mod resolver;

pub use types::{
    DnsCacheEntry, DnsQueryRecord, PendingQuery,
    DnsRecordType, DnsRecord, DnsRecordCacheEntry,
    MxRecord, SrvRecord,
    MAX_QUERY_CACHE, DEFAULT_TTL_MS,
};
pub use cache::{DNS_CACHE, DNS_STATS, DnsCache, DnsStats};
pub use resolver::{
    resolve, resolve_v4, resolve_v6,
    resolve_cname, resolve_mx, resolve_txt, resolve_ns, resolve_any,
    check_dns_timeouts, get_recent_queries, get_stats, clear_cache, init,
};
