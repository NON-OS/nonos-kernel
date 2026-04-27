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

use super::helpers::{parse_dns_name, skip_dns_name, skip_questions};
use crate::network::dns::DnsRecordType;
use alloc::string::String;
use alloc::vec::Vec;

pub(crate) fn parse_dns_response_a(data: &[u8]) -> Result<Vec<[u8; 4]>, &'static str> {
    let (addrs, _, _) = parse_dns_response_a_with_ttl(data)?;
    Ok(addrs)
}

pub(crate) fn parse_dns_response_a_with_ttl(
    data: &[u8],
) -> Result<(Vec<[u8; 4]>, u32, Vec<String>), &'static str> {
    if data.len() < 12 {
        return Err("dns short");
    }
    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut off = 12usize;
    skip_questions(data, &mut off, qd)?;
    let mut addrs = Vec::new();
    let mut cnames = Vec::new();
    let mut min_ttl: u32 = u32::MAX;
    for _ in 0..an {
        if off + 10 > data.len() {
            break;
        }
        skip_dns_name(data, &mut off)?;
        if off + 10 > data.len() {
            break;
        }
        let typ = u16::from_be_bytes([data[off], data[off + 1]]);
        off += 2;
        off += 2;
        let ttl = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        off += 4;
        let rdlen = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        if typ == DnsRecordType::A as u16 && rdlen == 4 && off + 4 <= data.len() {
            let mut a = [0u8; 4];
            a.copy_from_slice(&data[off..off + 4]);
            addrs.push(a);
            if ttl < min_ttl {
                min_ttl = ttl;
            }
        } else if typ == DnsRecordType::CNAME as u16 && off + rdlen <= data.len() {
            if let Ok(name) = parse_dns_name(data, off) {
                cnames.push(name);
                if ttl < min_ttl {
                    min_ttl = ttl;
                }
            }
        }
        off += rdlen;
    }
    if min_ttl == u32::MAX {
        min_ttl = 300;
    }
    Ok((addrs, min_ttl, cnames))
}

pub(crate) fn parse_dns_response_aaaa(data: &[u8]) -> Result<Vec<[u8; 16]>, &'static str> {
    let (addrs, _) = parse_dns_response_aaaa_with_ttl(data)?;
    Ok(addrs)
}

pub(crate) fn parse_dns_response_aaaa_with_ttl(
    data: &[u8],
) -> Result<(Vec<[u8; 16]>, u32), &'static str> {
    if data.len() < 12 {
        return Err("dns short");
    }
    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut off = 12usize;
    skip_questions(data, &mut off, qd)?;
    let mut addrs = Vec::new();
    let mut min_ttl: u32 = u32::MAX;
    for _ in 0..an {
        if off + 10 > data.len() {
            break;
        }
        skip_dns_name(data, &mut off)?;
        if off + 10 > data.len() {
            break;
        }
        let typ = u16::from_be_bytes([data[off], data[off + 1]]);
        off += 2;
        off += 2;
        let ttl = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        off += 4;
        let rdlen = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        if typ == DnsRecordType::AAAA as u16 && rdlen == 16 && off + 16 <= data.len() {
            let mut a = [0u8; 16];
            a.copy_from_slice(&data[off..off + 16]);
            addrs.push(a);
            if ttl < min_ttl {
                min_ttl = ttl;
            }
        }
        off += rdlen;
    }
    if min_ttl == u32::MAX {
        min_ttl = 300;
    }
    Ok((addrs, min_ttl))
}
