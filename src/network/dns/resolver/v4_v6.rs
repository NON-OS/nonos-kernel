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
use super::helpers::{record_failure, record_success};
use super::resolve::resolve;
use crate::network::ip::IpAddress;
use alloc::vec::Vec;

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
