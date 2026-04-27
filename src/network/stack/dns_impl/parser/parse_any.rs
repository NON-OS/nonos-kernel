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
use crate::network::dns::{DnsRecord, DnsRecordType, MxRecord};
use alloc::string::String;
use alloc::vec::Vec;

pub(crate) fn parse_dns_response_any(data: &[u8]) -> Result<Vec<DnsRecord>, &'static str> {
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
        if off + rdlen <= data.len() {
            match DnsRecordType::from_u16(typ) {
                Some(DnsRecordType::A) if rdlen == 4 => {
                    let mut a = [0u8; 4];
                    a.copy_from_slice(&data[off..off + 4]);
                    out.push(DnsRecord::A(a));
                }
                Some(DnsRecordType::AAAA) if rdlen == 16 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&data[off..off + 16]);
                    out.push(DnsRecord::AAAA(a));
                }
                Some(DnsRecordType::CNAME) => {
                    if let Ok(n) = parse_dns_name(data, off) {
                        out.push(DnsRecord::CNAME(n));
                    }
                }
                Some(DnsRecordType::MX) if rdlen >= 3 => {
                    let preference = u16::from_be_bytes([data[off], data[off + 1]]);
                    if let Ok(exchange) = parse_dns_name(data, off + 2) {
                        out.push(DnsRecord::MX(MxRecord { preference, exchange }));
                    }
                }
                Some(DnsRecordType::TXT) => {
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
                        out.push(DnsRecord::TXT(txt));
                    }
                }
                Some(DnsRecordType::NS) => {
                    if let Ok(n) = parse_dns_name(data, off) {
                        out.push(DnsRecord::NS(n));
                    }
                }
                Some(DnsRecordType::PTR) => {
                    if let Ok(n) = parse_dns_name(data, off) {
                        out.push(DnsRecord::PTR(n));
                    }
                }
                _ => {}
            }
        }
        off += rdlen;
    }
    Ok(out)
}
