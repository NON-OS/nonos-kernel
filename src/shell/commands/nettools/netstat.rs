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

use crate::graphics::framebuffer::{
    COLOR_GREEN, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW,
};
use crate::shell::output::print_line;

pub fn cmd_netstat() {
    use super::helpers::write_ip;

    print_line(b"Network Connections:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"Proto  Local Address      Foreign Address    State", COLOR_TEXT_DIM);

    if let Some(stack) = crate::network::stack::get_network_stack() {
        let sockets = stack.get_socket_info();
        if sockets.is_empty() {
            print_line(b"(no active connections)", COLOR_TEXT_DIM);
        } else {
            for sock in sockets.iter().take(10) {
                let mut line = [b' '; 64];
                line[..3].copy_from_slice(b"tcp");

                /* Local address: *:port */
                line[7] = b'*';
                line[8] = b':';
                let _ = write_port(&mut line[9..], sock.local_port);

                /* Remote address: ip:port */
                let remote_start = 19;
                let ip_len = write_ip(&mut line[remote_start..], sock.remote_ip);
                line[remote_start + ip_len] = b':';
                let _ = write_port(&mut line[remote_start + ip_len + 1..], sock.remote_port);

                /* State */
                let state_start = 39;
                let (state_str, slen): (&[u8], usize) = match sock.state {
                    0 => (b"CLOSED", 6),
                    1 => (b"LISTEN", 6),
                    2 => (b"SYN_SENT", 8),
                    3 => (b"SYN_RECV", 8),
                    4 => (b"ESTAB", 5),
                    5 => (b"FIN_WAIT", 8),
                    _ => (b"UNKNOWN", 7),
                };
                line[state_start..state_start + slen].copy_from_slice(state_str);

                let color = match sock.state {
                    4 => COLOR_GREEN,
                    1 => COLOR_YELLOW,
                    _ => COLOR_TEXT,
                };
                print_line(&line[..state_start + slen], color);
            }
        }
    } else {
        print_line(b"(network not initialized)", COLOR_TEXT_DIM);
    }
}

fn write_port(buf: &mut [u8], port: u16) -> usize {
    if port == 0 {
        buf[0] = b'*';
        return 1;
    }
    let mut n = port;
    let mut digits = [0u8; 5];
    let mut count = 0;
    while n > 0 {
        digits[count] = b'0' + (n % 10) as u8;
        n /= 10;
        count += 1;
    }
    for i in 0..count {
        buf[i] = digits[count - 1 - i];
    }
    count
}

pub fn cmd_arp() {
    print_line(b"ARP Table:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"Address           HWtype  HWaddress", COLOR_TEXT_DIM);
    print_line(b"127.0.0.1         loop    00:00:00:00:00:00", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);
    print_line(b"Note: ARP disabled on NYM interface", COLOR_YELLOW);
    print_line(b"Physical network access blocked", COLOR_TEXT_DIM);
}

pub fn cmd_ss() {
    print_line(b"Socket Statistics:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"Netid  State   Local Address:Port", COLOR_TEXT_DIM);

    print_line(b"tcp    LISTEN  127.0.0.1:1977  (nym)", COLOR_GREEN);
    print_line(b"tcp    LISTEN  127.0.0.1:1978  (nym-ctrl)", COLOR_GREEN);
    print_line(b"tcp    LISTEN  127.0.0.1:1979  (nym-dns)", COLOR_TEXT);
    print_line(b"unix   STREAM  /tmp/.nym/socket", COLOR_TEXT_DIM);

    print_line(b"", COLOR_TEXT);
    print_line(b"Total: 4 sockets", COLOR_TEXT_DIM);
}
