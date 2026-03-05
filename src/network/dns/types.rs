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

//! DNS types and constants

use alloc::string::String;
use alloc::vec::Vec;

/// Maximum number of cached DNS queries
pub const MAX_QUERY_CACHE: usize = 64;

/// Default TTL for cached entries (5 minutes)
pub const DEFAULT_TTL_MS: u64 = 300_000;

/// Default query timeout
pub(super) const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// DNS record type constants (RFC 1035, RFC 3596)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsRecordType {
    /// A - IPv4 address (RFC 1035)
    A = 1,
    /// NS - Nameserver (RFC 1035)
    NS = 2,
    /// CNAME - Canonical name (RFC 1035)
    CNAME = 5,
    /// SOA - Start of authority (RFC 1035)
    SOA = 6,
    /// PTR - Pointer (RFC 1035)
    PTR = 12,
    /// MX - Mail exchange (RFC 1035)
    MX = 15,
    /// TXT - Text record (RFC 1035)
    TXT = 16,
    /// AAAA - IPv6 address (RFC 3596)
    AAAA = 28,
    /// SRV - Service locator (RFC 2782)
    SRV = 33,
}

impl DnsRecordType {
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            1 => Some(DnsRecordType::A),
            2 => Some(DnsRecordType::NS),
            5 => Some(DnsRecordType::CNAME),
            6 => Some(DnsRecordType::SOA),
            12 => Some(DnsRecordType::PTR),
            15 => Some(DnsRecordType::MX),
            16 => Some(DnsRecordType::TXT),
            28 => Some(DnsRecordType::AAAA),
            33 => Some(DnsRecordType::SRV),
            _ => None,
        }
    }
}

/// MX record data
#[derive(Debug, Clone)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

/// SRV record data
#[derive(Debug, Clone)]
pub struct SrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

/// Generic DNS record
#[derive(Debug, Clone)]
pub enum DnsRecord {
    A([u8; 4]),
    AAAA([u8; 16]),
    CNAME(String),
    MX(MxRecord),
    TXT(String),
    NS(String),
    PTR(String),
    SRV(SrvRecord),
}

/// DNS query cache entry
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    pub hostname: String,
    pub addresses: Vec<[u8; 4]>,
    pub timestamp_ms: u64,
    pub ttl_ms: u64,
}

/// Extended cache entry supporting all record types
#[derive(Debug, Clone)]
pub struct DnsRecordCacheEntry {
    pub hostname: String,
    pub record_type: DnsRecordType,
    pub records: Vec<DnsRecord>,
    pub timestamp_ms: u64,
    pub ttl_ms: u64,
}

/// DNS query history entry
#[derive(Debug, Clone)]
pub struct DnsQueryRecord {
    pub hostname: String,
    pub timestamp_ms: u64,
    pub success: bool,
}

/// Pending DNS query
#[derive(Debug, Clone)]
pub struct PendingQuery {
    pub hostname: String,
    pub start_ms: u64,
    pub timeout_ms: u64,
}
