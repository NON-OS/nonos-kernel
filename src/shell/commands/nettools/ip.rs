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
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_ACCENT};
use crate::shell::commands::utils::trim_bytes;
use super::helpers::write_ip;
use super::ifconfig::cmd_ifconfig;
use super::netstat::cmd_arp;

pub fn cmd_ip(cmd: &[u8]) {
    let args = if cmd.len() > 3 {
        trim_bytes(&cmd[3..])
    } else {
        b"" as &[u8]
    };

    if args.is_empty() || args == b"addr" || args == b"a" {
        cmd_ifconfig();
    } else if args == b"route" || args == b"r" {
        cmd_route();
    } else if args == b"link" || args == b"l" {
        print_line(b"Network Links:", COLOR_TEXT_WHITE);
        print_line(b"============================================", COLOR_TEXT_DIM);
        print_line(b"1: lo: <LOOPBACK,UP> mtu 65536", COLOR_GREEN);
        print_line(b"    link/loopback 00:00:00:00:00:00", COLOR_TEXT_DIM);
        print_line(b"2: tor0: <TOR,UP> mtu 1500", COLOR_ACCENT);
        print_line(b"    link/tor [ANONYMOUS]", COLOR_YELLOW);
    } else if args.starts_with(b"neigh") {
        cmd_arp();
    } else {
        print_line(b"Usage: ip [addr|route|link|neigh]", COLOR_TEXT_DIM);
    }
}

pub fn cmd_route() {
    print_line(b"Routing Table:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"Destination     Gateway         Iface", COLOR_TEXT_DIM);

    print_line(b"127.0.0.0/8     -               lo", COLOR_TEXT);

    if let Some(stack) = crate::network::stack::get_network_stack() {
        if let Some((ip, prefix)) = stack.get_ipv4_config() {
            let mut local_line = [0u8; 64];
            let ip_len = write_ip(&mut local_line[0..], [ip[0], ip[1], ip[2], 0]);
            local_line[ip_len..ip_len+1].copy_from_slice(b"/");
            local_line[ip_len+1] = b'0' + (prefix / 10);
            local_line[ip_len+2] = b'0' + (prefix % 10);
            for i in ip_len+3..16 {
                local_line[i] = b' ';
            }
            local_line[16..17].copy_from_slice(b"-");
            for i in 17..32 {
                local_line[i] = b' ';
            }
            local_line[32..36].copy_from_slice(b"eth0");
            print_line(&local_line[..36], COLOR_TEXT);
        }

        if let Some(gw) = stack.get_gateway_v4() {
            let mut default_line = [0u8; 64];
            default_line[..16].copy_from_slice(b"0.0.0.0/0       ");
            let gw_len = write_ip(&mut default_line[16..], gw);
            for i in 16+gw_len..32 {
                default_line[i] = b' ';
            }
            default_line[32..36].copy_from_slice(b"eth0");
            print_line(&default_line[..36], COLOR_GREEN);
        }
    }
}
