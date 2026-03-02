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

use crate::shell::commands::network::*;
use crate::shell::commands::nettools::*;
use crate::shell::commands::utils::starts_with;

pub fn try_dispatch_network(cmd: &[u8]) -> bool {
    if cmd == b"net" || cmd == b"network" {
        cmd_net();
    } else if cmd == b"anon" || cmd == b"anonymous" {
        cmd_anon();
    } else if cmd == b"anyone" || cmd == b"anyone.io" {
        cmd_anyone();
    } else if cmd == b"wifi" || starts_with(cmd, b"wifi ") {
        cmd_wifi(cmd);
    } else if cmd == b"ifconfig" {
        cmd_ifconfig();
    } else if cmd == b"ip" || starts_with(cmd, b"ip ") {
        cmd_ip(cmd);
    } else if cmd == b"route" {
        cmd_route();
    } else if cmd == b"ping" || starts_with(cmd, b"ping ") {
        cmd_ping(cmd);
    } else if cmd == b"dns" || starts_with(cmd, b"dns ") {
        cmd_dns(cmd);
    } else if cmd == b"netstat" {
        cmd_netstat();
    } else if cmd == b"arp" {
        cmd_arp();
    } else if cmd == b"ss" {
        cmd_ss();
    } else if cmd == b"nslookup" || starts_with(cmd, b"nslookup ") {
        cmd_nslookup(cmd);
    } else if cmd == b"traceroute" || starts_with(cmd, b"traceroute ") {
        cmd_traceroute(cmd);
    } else if cmd == b"wget" || starts_with(cmd, b"wget ") {
        cmd_wget(cmd);
    } else if cmd == b"curl" || starts_with(cmd, b"curl ") {
        cmd_curl(cmd);
    } else {
        return false;
    }
    true
}
