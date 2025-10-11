//! DNS A resolver backed by smoltcp UDP via NetworkStack.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use super::ip::IpAddress;

pub fn resolve(hostname: &str) -> Result<Vec<IpAddress>, &'static str> {
    if let Some(ns) = super::get_network_stack() {
        let addrs = ns.dns_query_a(hostname, 3_000)?;
        Ok(addrs.into_iter().map(IpAddress::V4).collect())
    } else {
        Err("network not initialized")
    }
}

pub fn resolve_v4(hostname: &str) -> Result<[u8; 4], &'static str> {
    let v = resolve(hostname)?;
    for a in v {
        if let IpAddress::V4(v4) = a { return Ok(v4); }
    }
    Err("no A record")
}

/* Timeouts hook (no-op) */
pub fn check_dns_timeouts() {}
