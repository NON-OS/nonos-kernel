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

use crate::network::dns::{DnsRecord, DnsRecordType, MxRecord};

fn skip_dns_name(data: &[u8], off: &mut usize) -> Result<(), &'static str> {
    if *off >= data.len() { return Err("dns name overflow"); }

    if data[*off] & 0xC0 == 0xC0 {
        *off += 2;
    } else {
        while *off < data.len() && data[*off] != 0 {
            let len = data[*off] as usize;
            if len > 63 { return Err("dns invalid label"); }
            *off += 1 + len;
        }
        if *off < data.len() { *off += 1; }
    }
    Ok(())
}

fn parse_dns_name(data: &[u8], off: usize) -> Result<String, &'static str> {
    let mut name = String::new();
    let mut pos = off;
    let mut jumps = 0;

    while pos < data.len() {
        let len = data[pos];
        if len == 0 {
            break;
        } else if len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() { return Err("dns ptr overflow"); }
            let ptr = ((len as usize & 0x3F) << 8) | data[pos + 1] as usize;
            if ptr >= data.len() { return Err("dns invalid ptr"); }
            jumps += 1;
            if jumps > 10 { return Err("dns too many jumps"); }
            pos = ptr;
        } else {
            let label_len = len as usize;
            if pos + 1 + label_len > data.len() { return Err("dns label overflow"); }
            if !name.is_empty() { name.push('.'); }
            for i in 0..label_len {
                name.push(data[pos + 1 + i] as char);
            }
            pos += 1 + label_len;
        }
    }

    if name.is_empty() {
        name.push('.');
    }

    Ok(name)
}

fn skip_questions(data: &[u8], off: &mut usize, qd_count: usize) -> Result<(), &'static str> {
    for _ in 0..qd_count {
        skip_dns_name(data, off)?;
        *off += 4;
        if *off > data.len() { return Err("dns malformed qd"); }
    }
    Ok(())
}

pub(crate) fn parse_dns_response_a(data: &[u8]) -> Result<Vec<[u8; 4]>, &'static str> {
    if data.len() < 12 { return Err("dns short"); }
    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut off = 12usize;
    skip_questions(data, &mut off, qd)?;

    let mut out = Vec::new();
    for _ in 0..an {
        if off + 10 > data.len() { break; }
        skip_dns_name(data, &mut off)?;
        if off + 10 > data.len() { break; }

        let typ = u16::from_be_bytes([data[off], data[off+1]]); off += 2;
        off += 2;
        off += 4;
        let rdlen = u16::from_be_bytes([data[off], data[off+1]]) as usize; off += 2;

        if typ == DnsRecordType::A as u16 && rdlen == 4 && off + 4 <= data.len() {
            let mut a = [0u8; 4];
            a.copy_from_slice(&data[off..off+4]);
            out.push(a);
        }
        off += rdlen;
    }
    Ok(out)
}

pub(crate) fn parse_dns_response_aaaa(data: &[u8]) -> Result<Vec<[u8; 16]>, &'static str> {
    if data.len() < 12 { return Err("dns short"); }
    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut off = 12usize;
    skip_questions(data, &mut off, qd)?;

    let mut out = Vec::new();
    for _ in 0..an {
        if off + 10 > data.len() { break; }
        skip_dns_name(data, &mut off)?;
        if off + 10 > data.len() { break; }

        let typ = u16::from_be_bytes([data[off], data[off+1]]); off += 2;
        off += 2;
        off += 4;
        let rdlen = u16::from_be_bytes([data[off], data[off+1]]) as usize; off += 2;

        if typ == DnsRecordType::AAAA as u16 && rdlen == 16 && off + 16 <= data.len() {
            let mut a = [0u8; 16];
            a.copy_from_slice(&data[off..off+16]);
            out.push(a);
        }
        off += rdlen;
    }
    Ok(out)
}

pub(crate) fn parse_dns_response_cname(data: &[u8]) -> Result<Vec<String>, &'static str> {
    if data.len() < 12 { return Err("dns short"); }
    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut off = 12usize;
    skip_questions(data, &mut off, qd)?;

    let mut out = Vec::new();
    for _ in 0..an {
        if off + 10 > data.len() { break; }
        skip_dns_name(data, &mut off)?;
        if off + 10 > data.len() { break; }

        let typ = u16::from_be_bytes([data[off], data[off+1]]); off += 2;
        off += 2;
        off += 4;
        let rdlen = u16::from_be_bytes([data[off], data[off+1]]) as usize; off += 2;

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
    if data.len() < 12 { return Err("dns short"); }
    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut off = 12usize;
    skip_questions(data, &mut off, qd)?;

    let mut out = Vec::new();
    for _ in 0..an {
        if off + 10 > data.len() { break; }
        skip_dns_name(data, &mut off)?;
        if off + 10 > data.len() { break; }

        let typ = u16::from_be_bytes([data[off], data[off+1]]); off += 2;
        off += 2;
        off += 4;
        let rdlen = u16::from_be_bytes([data[off], data[off+1]]) as usize; off += 2;

        if typ == DnsRecordType::MX as u16 && rdlen >= 3 && off + rdlen <= data.len() {
            let preference = u16::from_be_bytes([data[off], data[off+1]]);
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
    if data.len() < 12 { return Err("dns short"); }
    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut off = 12usize;
    skip_questions(data, &mut off, qd)?;

    let mut out = Vec::new();
    for _ in 0..an {
        if off + 10 > data.len() { break; }
        skip_dns_name(data, &mut off)?;
        if off + 10 > data.len() { break; }

        let typ = u16::from_be_bytes([data[off], data[off+1]]); off += 2;
        off += 2;
        off += 4;
        let rdlen = u16::from_be_bytes([data[off], data[off+1]]) as usize; off += 2;

        if typ == DnsRecordType::TXT as u16 && off + rdlen <= data.len() {
            let mut txt = String::new();
            let end = off + rdlen;
            let mut pos = off;
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
    if data.len() < 12 { return Err("dns short"); }
    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut off = 12usize;
    skip_questions(data, &mut off, qd)?;

    let mut out = Vec::new();
    for _ in 0..an {
        if off + 10 > data.len() { break; }
        skip_dns_name(data, &mut off)?;
        if off + 10 > data.len() { break; }

        let typ = u16::from_be_bytes([data[off], data[off+1]]); off += 2;
        off += 2;
        off += 4;
        let rdlen = u16::from_be_bytes([data[off], data[off+1]]) as usize; off += 2;

        if typ == DnsRecordType::NS as u16 && off + rdlen <= data.len() {
            if let Ok(name) = parse_dns_name(data, off) {
                out.push(name);
            }
        }
        off += rdlen;
    }
    Ok(out)
}

pub(crate) fn parse_dns_response_any(data: &[u8]) -> Result<Vec<DnsRecord>, &'static str> {
    if data.len() < 12 { return Err("dns short"); }
    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut off = 12usize;
    skip_questions(data, &mut off, qd)?;

    let mut out = Vec::new();
    for _ in 0..an {
        if off + 10 > data.len() { break; }
        skip_dns_name(data, &mut off)?;
        if off + 10 > data.len() { break; }

        let typ = u16::from_be_bytes([data[off], data[off+1]]); off += 2;
        off += 2;
        off += 4;
        let rdlen = u16::from_be_bytes([data[off], data[off+1]]) as usize; off += 2;

        if off + rdlen <= data.len() {
            match DnsRecordType::from_u16(typ) {
                Some(DnsRecordType::A) if rdlen == 4 => {
                    let mut a = [0u8; 4];
                    a.copy_from_slice(&data[off..off+4]);
                    out.push(DnsRecord::A(a));
                }
                Some(DnsRecordType::AAAA) if rdlen == 16 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&data[off..off+16]);
                    out.push(DnsRecord::AAAA(a));
                }
                Some(DnsRecordType::CNAME) => {
                    if let Ok(name) = parse_dns_name(data, off) {
                        out.push(DnsRecord::CNAME(name));
                    }
                }
                Some(DnsRecordType::MX) if rdlen >= 3 => {
                    let preference = u16::from_be_bytes([data[off], data[off+1]]);
                    if let Ok(exchange) = parse_dns_name(data, off + 2) {
                        out.push(DnsRecord::MX(MxRecord { preference, exchange }));
                    }
                }
                Some(DnsRecordType::TXT) => {
                    let mut txt = String::new();
                    let end = off + rdlen;
                    let mut pos = off;
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
                        out.push(DnsRecord::TXT(txt));
                    }
                }
                Some(DnsRecordType::NS) => {
                    if let Ok(name) = parse_dns_name(data, off) {
                        out.push(DnsRecord::NS(name));
                    }
                }
                Some(DnsRecordType::PTR) => {
                    if let Ok(name) = parse_dns_name(data, off) {
                        out.push(DnsRecord::PTR(name));
                    }
                }
                _ => {}
            }
        }
        off += rdlen;
    }
    Ok(out)
}