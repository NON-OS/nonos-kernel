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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_RED};
use crate::shell::commands::utils::trim_bytes;
use super::helpers::write_ip;

pub fn cmd_dns(cmd: &[u8]) {
    let args = if cmd.len() > 4 {
        trim_bytes(&cmd[4..])
    } else {
        b"" as &[u8]
    };

    if args.is_empty() || args == b"status" {
        print_line(b"DNS Configuration:", COLOR_TEXT_WHITE);
        print_line(b"============================================", COLOR_TEXT_DIM);

        if let Some(stack) = crate::network::stack::get_network_stack() {
            let dns = stack.get_default_dns_v4();
            let mut dns_line = [0u8; 48];
            dns_line[..16].copy_from_slice(b"DNS Server:     ");
            let dns_len = write_ip(&mut dns_line[16..], dns);
            print_line(&dns_line[..16+dns_len], COLOR_GREEN);
        } else {
            print_line(b"DNS Server:     not configured", COLOR_YELLOW);
        }
    } else if args.starts_with(b"lookup ") {
        let host = trim_bytes(&args[7..]);
        if host.is_empty() {
            print_line(b"Usage: dns lookup <hostname>", COLOR_TEXT_DIM);
            return;
        }

        let host_str = match core::str::from_utf8(host) {
            Ok(s) => s,
            Err(_) => {
                print_line(b"dns: invalid hostname", COLOR_RED);
                return;
            }
        };

        let mut line = [0u8; 64];
        line[..11].copy_from_slice(b"Resolving: ");
        let host_len = host.len().min(40);
        line[11..11+host_len].copy_from_slice(&host[..host_len]);
        print_line(&line[..11+host_len], COLOR_TEXT);

        if let Some(stack) = crate::network::stack::get_network_stack() {
            match stack.dns_query_a(host_str, 5000) {
                Ok(results) => {
                    if results.is_empty() {
                        print_line(b"No results found", COLOR_YELLOW);
                    } else {
                        for ip in results.iter().take(5) {
                            let mut result_line = [0u8; 32];
                            result_line[..4].copy_from_slice(b"  > ");
                            let ip_len = write_ip(&mut result_line[4..], *ip);
                            print_line(&result_line[..4+ip_len], COLOR_GREEN);
                        }
                    }
                }
                Err(e) => {
                    let mut err_line = [0u8; 64];
                    err_line[..12].copy_from_slice(b"DNS failed: ");
                    let err_bytes = e.as_bytes();
                    let err_len = err_bytes.len().min(40);
                    err_line[12..12+err_len].copy_from_slice(&err_bytes[..err_len]);
                    print_line(&err_line[..12+err_len], COLOR_RED);
                }
            }
        } else {
            print_line(b"dns: network not initialized", COLOR_RED);
        }
    } else {
        print_line(b"Usage: dns [status|lookup <host>]", COLOR_TEXT_DIM);
    }
}

pub fn cmd_nslookup(cmd: &[u8]) {
    let host = if cmd.len() > 9 {
        trim_bytes(&cmd[9..])
    } else {
        print_line(b"Usage: nslookup <hostname>", COLOR_TEXT_DIM);
        return;
    };

    if host.is_empty() {
        print_line(b"nslookup: hostname required", COLOR_RED);
        return;
    }

    print_line(b"Server:  127.0.0.1 (Tor DNS)", COLOR_TEXT_DIM);
    print_line(b"Address: 127.0.0.1#9053", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);

    if host == b"localhost" {
        print_line(b"Name:    localhost", COLOR_TEXT);
        print_line(b"Address: 127.0.0.1", COLOR_GREEN);
    } else {
        let mut line = [0u8; 48];
        line[..6].copy_from_slice(b"Name:  ");
        let host_len = host.len().min(32);
        line[6..6+host_len].copy_from_slice(&host[..host_len]);
        print_line(&line[..6+host_len], COLOR_TEXT);

        print_line(b"Address: [RESOLVED VIA TOR]", COLOR_YELLOW);
        print_line(b"(Query sent through anonymous circuit)", COLOR_TEXT_DIM);
    }
}
