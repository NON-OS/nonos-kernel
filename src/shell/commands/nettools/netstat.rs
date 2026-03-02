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
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW};

pub fn cmd_netstat() {
    print_line(b"Network Connections:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"Proto  Local Address      Foreign Address    State", COLOR_TEXT_DIM);

    if let Some(stack) = crate::network::stack::get_network_stack() {
        let sockets = stack.get_socket_info();
        if sockets.is_empty() {
            print_line(b"(no active connections)", COLOR_TEXT_DIM);
        } else {
            for _sock in sockets.iter().take(10) {
                let mut line = [0u8; 64];
                line[..6].copy_from_slice(b"tcp   ");
                print_line(&line[..6], COLOR_TEXT);
            }
        }
    } else {
        print_line(b"(network not initialized)", COLOR_TEXT_DIM);
    }
}

pub fn cmd_arp() {
    print_line(b"ARP Table:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"Address           HWtype  HWaddress", COLOR_TEXT_DIM);
    print_line(b"127.0.0.1         loop    00:00:00:00:00:00", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);
    print_line(b"Note: ARP disabled on Tor interface", COLOR_YELLOW);
    print_line(b"Physical network access blocked", COLOR_TEXT_DIM);
}

pub fn cmd_ss() {
    print_line(b"Socket Statistics:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"Netid  State   Local Address:Port", COLOR_TEXT_DIM);

    print_line(b"tcp    LISTEN  127.0.0.1:9050  (tor)", COLOR_GREEN);
    print_line(b"tcp    LISTEN  127.0.0.1:9051  (tor-ctrl)", COLOR_GREEN);
    print_line(b"tcp    LISTEN  127.0.0.1:9053  (tor-dns)", COLOR_TEXT);
    print_line(b"unix   STREAM  /tmp/.tor/socket", COLOR_TEXT_DIM);

    print_line(b"", COLOR_TEXT);
    print_line(b"Total: 4 sockets", COLOR_TEXT_DIM);
}
