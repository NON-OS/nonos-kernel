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

use super::super::cache::DNS_STATS;
use super::super::types::{DnsRecord, MxRecord};
use super::helpers::{record_failure, record_success};
use alloc::string::String;
use alloc::vec::Vec;

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
