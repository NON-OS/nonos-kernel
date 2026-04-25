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
use crate::network::dns::{DnsRecordType, MxRecord};
use alloc::string::String;
use alloc::vec::Vec;

pub(crate) fn parse_dns_response_cname(data: &[u8]) -> Result<Vec<String>, &'static str> {
    if data.len() < 12 {
        return Err("dns short");
    }
    let (qd, an) = (
        u16::from_be_bytes([data[4], data[5]]) as usize,
        u16::from_be_bytes([data[6], data[7]]) as usize,
    );
    let mut off = 12usize;
    skip_questions(data, &mut off, qd)?;
    let mut out = Vec::new();
    for _ in 0..an {
        if off + 10 > data.len() {
            break;
        }
        skip_dns_name(data, &mut off)?;
        if off + 10 > data.len() {
            break;
        }
        let typ = u16::from_be_bytes([data[off], data[off + 1]]);
        off += 8;
        let rdlen = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        if typ == DnsRecordType::CNAME as u16 && off + rdlen <= data.len() {
            if let Ok(name) = parse_dns_name(data, off) {
                out.push(name);
            }
        }
        off += rdlen;
    }
    Ok(out)
}

pub(crate) fn parse_dns_response_mx(data: &[u8]) -> Result<Vec<MxRecord>, &'static str> {
    if data.len() < 12 {
        return Err("dns short");
    }
    let (qd, an) = (
        u16::from_be_bytes([data[4], data[5]]) as usize,
        u16::from_be_bytes([data[6], data[7]]) as usize,
    );
    let mut off = 12usize;
    skip_questions(data, &mut off, qd)?;
    let mut out = Vec::new();
    for _ in 0..an {
        if off + 10 > data.len() {
            break;
        }
        skip_dns_name(data, &mut off)?;
        if off + 10 > data.len() {
            break;
        }
        let typ = u16::from_be_bytes([data[off], data[off + 1]]);
        off += 8;
        let rdlen = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        if typ == DnsRecordType::MX as u16 && rdlen >= 3 && off + rdlen <= data.len() {
            let preference = u16::from_be_bytes([data[off], data[off + 1]]);
            if let Ok(exchange) = parse_dns_name(data, off + 2) {
                out.push(MxRecord { preference, exchange });
            }
        }
        off += rdlen;
    }
    out.sort_by_key(|mx| mx.preference);
    Ok(out)
}

pub(crate) fn parse_dns_response_txt(data: &[u8]) -> Result<Vec<String>, &'static str> {
    if data.len() < 12 {
        return Err("dns short");
    }
    let (qd, an) = (
        u16::from_be_bytes([data[4], data[5]]) as usize,
        u16::from_be_bytes([data[6], data[7]]) as usize,
    );
    let mut off = 12usize;
    skip_questions(data, &mut off, qd)?;
    let mut out = Vec::new();
    for _ in 0..an {
        if off + 10 > data.len() {
            break;
        }
        skip_dns_name(data, &mut off)?;
        if off + 10 > data.len() {
            break;
        }
        let typ = u16::from_be_bytes([data[off], data[off + 1]]);
        off += 8;
        let rdlen = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        if typ == DnsRecordType::TXT as u16 && off + rdlen <= data.len() {
            let (mut txt, end, mut pos) = (String::new(), off + rdlen, off);
            while pos < end {
                let len = data[pos] as usize;
                pos += 1;
                if pos + len <= end {
                    for i in 0..len {
                        txt.push(data[pos + i] as char);
                    }
                    pos += len;
                } else {
                    break;
                }
            }
            if !txt.is_empty() {
                out.push(txt);
            }
        }
        off += rdlen;
    }
    Ok(out)
}

pub(crate) fn parse_dns_response_ns(data: &[u8]) -> Result<Vec<String>, &'static str> {
    if data.len() < 12 {
        return Err("dns short");
    }
    let (qd, an) = (
        u16::from_be_bytes([data[4], data[5]]) as usize,
        u16::from_be_bytes([data[6], data[7]]) as usize,
    );
    let mut off = 12usize;
    skip_questions(data, &mut off, qd)?;
    let mut out = Vec::new();
    for _ in 0..an {
        if off + 10 > data.len() {
            break;
        }
        skip_dns_name(data, &mut off)?;
        if off + 10 > data.len() {
            break;
        }
        let typ = u16::from_be_bytes([data[off], data[off + 1]]);
        off += 8;
        let rdlen = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        if typ == DnsRecordType::NS as u16 && off + rdlen <= data.len() {
            if let Ok(name) = parse_dns_name(data, off) {
                out.push(name);
            }
        }
        off += rdlen;
    }
    Ok(out)
}
