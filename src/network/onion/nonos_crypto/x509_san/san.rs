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
use super::super::types::X509Certificate;
use super::super::x509_core::X509;

impl X509 {
    pub fn get_san_dns_names(cert: &X509Certificate) -> Option<Vec<String>> {
        let tbs = &cert.tbs_certificate;
        let mut names = Vec::new();
        let san_oid = [0x55, 0x1D, 0x11];
        let mut i = 0;
        while i + 3 < tbs.len() {
            if tbs[i..].starts_with(&san_oid) {
                i += 3;
                while i < tbs.len() && tbs[i] != 0x04 {
                    i += 1;
                }
                if i >= tbs.len() {
                    break;
                }
                i += 1;
                if i >= tbs.len() {
                    break;
                }
                let (len, new_i) = parse_length(tbs, i);
                i = new_i;
                let end = (i + len).min(tbs.len());
                while i < end {
                    if tbs[i] == 0x82 {
                        i += 1;
                        if i >= end {
                            break;
                        }
                        let name_len = tbs[i] as usize;
                        i += 1;
                        if i + name_len <= end {
                            if let Ok(name) = core::str::from_utf8(&tbs[i..i + name_len]) {
                                names.push(String::from(name));
                            }
                        }
                        i += name_len;
                    } else {
                        i += 1;
                    }
                }
                break;
            }
            i += 1;
        }
        if names.is_empty() { None } else { Some(names) }
    }
}

fn parse_length(tbs: &[u8], mut i: usize) -> (usize, usize) {
    if tbs[i] & 0x80 == 0 {
        let l = tbs[i] as usize;
        (l, i + 1)
    } else {
        let len_bytes = (tbs[i] & 0x7F) as usize;
        i += 1;
        let mut l = 0usize;
        for _ in 0..len_bytes {
            if i >= tbs.len() {
                break;
            }
            l = (l << 8) | tbs[i] as usize;
            i += 1;
        }
        (l, i)
    }
}
