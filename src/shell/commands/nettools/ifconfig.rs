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
use super::helpers::{write_ip, write_mac, write_u64};

pub fn cmd_ifconfig() {
    print_line(b"Network Interfaces:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);

    if let Some(stack) = crate::network::stack::get_network_stack() {
        let (link_up, link_speed, full_duplex) = crate::drivers::e1000::get_link_status()
            .unwrap_or((false, 0, false));

        let connected = crate::network::stack::is_network_connected();

        if link_up && connected {
            print_line(b"eth0: flags=4163<UP,BROADCAST,RUNNING,CONNECTED>", COLOR_GREEN);
        } else if link_up {
            print_line(b"eth0: flags=4163<UP,BROADCAST,RUNNING> (NO CONNECTIVITY)", COLOR_YELLOW);
        } else {
            print_line(b"eth0: flags=4099<UP,BROADCAST> (NO LINK)", COLOR_RED);
        }

        if let Some((ip, prefix)) = stack.get_ipv4_config() {
            let mut ip_line = [0u8; 64];
            ip_line[..13].copy_from_slice(b"        inet ");
            let ip_len = write_ip(&mut ip_line[13..], ip);
            ip_line[13+ip_len..13+ip_len+2].copy_from_slice(b"/");
            ip_line[14+ip_len] = b'0' + (prefix / 10);
            ip_line[15+ip_len] = b'0' + (prefix % 10);
            print_line(&ip_line[..16+ip_len], COLOR_TEXT);
        }

        if let Some(gw) = stack.get_gateway_v4() {
            let mut gw_line = [0u8; 48];
            gw_line[..16].copy_from_slice(b"        gateway ");
            let gw_len = write_ip(&mut gw_line[16..], gw);
            print_line(&gw_line[..16+gw_len], COLOR_TEXT);
        }

        let mac = stack.get_mac_address();
        let mut mac_line = [0u8; 48];
        mac_line[..14].copy_from_slice(b"        ether ");
        let mac_len = write_mac(&mut mac_line[14..], mac);
        print_line(&mac_line[..14+mac_len], COLOR_TEXT_DIM);

        if link_up && link_speed > 0 {
            let mut speed_line = [0u8; 48];
            speed_line[..14].copy_from_slice(b"        speed ");
            let mut pos = 14;
            if link_speed >= 1000 {
                speed_line[pos] = b'0' + ((link_speed / 1000) as u8);
                pos += 1;
                speed_line[pos..pos+4].copy_from_slice(b"Gbps");
                pos += 4;
            } else {
                if link_speed >= 100 {
                    speed_line[pos] = b'0' + ((link_speed / 100) as u8);
                    pos += 1;
                }
                if link_speed >= 10 {
                    speed_line[pos] = b'0' + (((link_speed / 10) % 10) as u8);
                    pos += 1;
                }
                speed_line[pos] = b'0' + ((link_speed % 10) as u8);
                pos += 1;
                speed_line[pos..pos+4].copy_from_slice(b"Mbps");
                pos += 4;
            }
            if full_duplex {
                speed_line[pos..pos+12].copy_from_slice(b" full-duplex");
                pos += 12;
            }
            print_line(&speed_line[..pos], COLOR_TEXT_DIM);
        }

        if let Some(stats) = crate::drivers::e1000::get_stats() {
            print_line(b"        --- Packet Statistics ---", COLOR_TEXT_WHITE);

            let mut rx_line = [0u8; 64];
            rx_line[..12].copy_from_slice(b"        RX: ");
            let mut pos = 12;
            pos += write_u64(&mut rx_line[pos..], stats.rx_packets);
            rx_line[pos..pos+9].copy_from_slice(b" packets ");
            pos += 9;
            pos += write_u64(&mut rx_line[pos..], stats.rx_bytes);
            rx_line[pos..pos+6].copy_from_slice(b" bytes");
            pos += 6;
            print_line(&rx_line[..pos], if stats.rx_packets > 0 { COLOR_GREEN } else { COLOR_YELLOW });

            let mut tx_line = [0u8; 64];
            tx_line[..12].copy_from_slice(b"        TX: ");
            pos = 12;
            pos += write_u64(&mut tx_line[pos..], stats.tx_packets);
            tx_line[pos..pos+9].copy_from_slice(b" packets ");
            pos += 9;
            pos += write_u64(&mut tx_line[pos..], stats.tx_bytes);
            tx_line[pos..pos+6].copy_from_slice(b" bytes");
            pos += 6;
            print_line(&tx_line[..pos], if stats.tx_packets > 0 { COLOR_GREEN } else { COLOR_YELLOW });

            if stats.rx_errors > 0 || stats.tx_errors > 0 {
                let mut err_line = [0u8; 48];
                err_line[..15].copy_from_slice(b"        errors ");
                pos = 15;
                pos += write_u64(&mut err_line[pos..], stats.rx_errors + stats.tx_errors);
                print_line(&err_line[..pos], COLOR_RED);
            }
        }
    } else {
        print_line(b"eth0: <DOWN>", COLOR_RED);
        print_line(b"        Network not initialized", COLOR_TEXT_DIM);
    }

    print_line(b"", COLOR_TEXT);
    print_line(b"lo: flags=73<UP,LOOPBACK,RUNNING>", COLOR_GREEN);
    print_line(b"        inet 127.0.0.1/8", COLOR_TEXT);
}
