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
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_RED};
use crate::shell::commands::utils::trim_bytes;
use super::helpers::parse_ipv4;

pub fn cmd_ping(cmd: &[u8]) {
    let target = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        print_line(b"Usage: ping <ip_address>", COLOR_TEXT_DIM);
        print_line(b"Example: ping 10.0.2.2", COLOR_TEXT_DIM);
        return;
    };

    if target.is_empty() {
        print_line(b"ping: IP address required", COLOR_RED);
        return;
    }

    let ip = match parse_ipv4(target) {
        Some(ip) => ip,
        None => {
            print_line(b"ping: invalid IP address format", COLOR_RED);
            print_line(b"Example: ping 10.0.2.2", COLOR_TEXT_DIM);
            return;
        }
    };

    let mut line = [0u8; 64];
    line[..6].copy_from_slice(b"PING ");
    let target_len = target.len().min(32);
    line[5..5+target_len].copy_from_slice(&target[..target_len]);
    print_line(&line[..5+target_len], COLOR_TEXT_WHITE);

    let stack = match crate::network::stack::get_network_stack() {
        Some(s) => s,
        None => {
            print_line(b"ping: network not initialized", COLOR_RED);
            return;
        }
    };

    if !stack.has_route_to(ip) {
        print_line(b"ping: no route to host", COLOR_RED);
        return;
    }

    let mut sent = 0u32;
    let mut received = 0u32;
    let mut total_rtt = 0u64;

    use crate::network::stack::async_ops::{self, AsyncResult};

    for seq in 1..=2u16 {
        sent += 1;

        if async_ops::ping_start(ip, seq, 200).is_err() {
            print_line(b"ping: send failed", COLOR_RED);
            continue;
        }

        let mut got_reply = false;
        for _poll_num in 0..50u32 {
            match async_ops::ping_poll() {
                AsyncResult::Ready(rtt) => {
                    received += 1;
                    total_rtt += rtt;
                    got_reply = true;

                    let mut reply = [0u8; 80];
                    reply[..15].copy_from_slice(b"64 bytes from ");
                    let ip_len = target_len.min(20);
                    reply[15..15+ip_len].copy_from_slice(&target[..ip_len]);
                    let mut pos = 15 + ip_len;
                    reply[pos..pos+6].copy_from_slice(b": seq=");
                    pos += 6;
                    reply[pos] = b'0' + (seq as u8);
                    pos += 1;
                    reply[pos..pos+6].copy_from_slice(b" time=");
                    pos += 6;
                    if rtt >= 100 {
                        reply[pos] = b'0' + ((rtt / 100) % 10) as u8;
                        pos += 1;
                    }
                    if rtt >= 10 {
                        reply[pos] = b'0' + ((rtt / 10) % 10) as u8;
                        pos += 1;
                    }
                    reply[pos] = b'0' + (rtt % 10) as u8;
                    pos += 1;
                    reply[pos..pos+2].copy_from_slice(b"ms");
                    pos += 2;
                    print_line(&reply[..pos], COLOR_GREEN);
                    break;
                }
                AsyncResult::Error(_) => {
                    break;
                }
                AsyncResult::Pending => {
                    x86_64::instructions::interrupts::enable();
                    for _ in 0..500 { core::hint::spin_loop(); }
                    x86_64::instructions::interrupts::disable();
                }
            }
        }

        if !got_reply {
            let mut timeout_msg = [0u8; 64];
            timeout_msg[..22].copy_from_slice(b"Request timeout seq=");
            timeout_msg[22] = b'0' + (seq as u8);
            print_line(&timeout_msg[..23], COLOR_RED);
        }

        async_ops::ping_cancel();
    }

    print_line(b"", COLOR_TEXT);
    let mut summary = [0u8; 80];
    summary[..4].copy_from_slice(b"--- ");
    let tlen = target_len.min(20);
    summary[4..4+tlen].copy_from_slice(&target[..tlen]);
    summary[4+tlen..4+tlen+17].copy_from_slice(b" ping statistics ");
    summary[21+tlen..21+tlen+3].copy_from_slice(b"---");
    print_line(&summary[..24+tlen], COLOR_TEXT_WHITE);

    let mut stats = [0u8; 64];
    stats[0] = b'0' + (sent as u8);
    stats[1..14].copy_from_slice(b" transmitted, ");
    stats[14] = b'0' + (received as u8);
    stats[15..25].copy_from_slice(b" received, ");
    let loss = if sent > 0 { ((sent - received) * 100) / sent } else { 0 };
    if loss >= 100 {
        stats[25..28].copy_from_slice(b"100");
        stats[28..40].copy_from_slice(b"% packet loss");
        print_line(&stats[..40], if loss > 0 { COLOR_RED } else { COLOR_GREEN });
    } else if loss >= 10 {
        stats[25] = b'0' + ((loss / 10) as u8);
        stats[26] = b'0' + ((loss % 10) as u8);
        stats[27..39].copy_from_slice(b"% packet loss");
        print_line(&stats[..39], if loss > 0 { COLOR_RED } else { COLOR_GREEN });
    } else {
        stats[25] = b'0' + (loss as u8);
        stats[26..38].copy_from_slice(b"% packet loss");
        print_line(&stats[..38], if loss > 0 { COLOR_RED } else { COLOR_GREEN });
    }

    if received > 0 {
        let avg_rtt = total_rtt / received as u64;
        let mut rtt_line = [0u8; 48];
        rtt_line[..10].copy_from_slice(b"rtt avg = ");
        let mut pos = 10;
        if avg_rtt >= 100 {
            rtt_line[pos] = b'0' + ((avg_rtt / 100) % 10) as u8;
            pos += 1;
        }
        if avg_rtt >= 10 {
            rtt_line[pos] = b'0' + ((avg_rtt / 10) % 10) as u8;
            pos += 1;
        }
        rtt_line[pos] = b'0' + (avg_rtt % 10) as u8;
        pos += 1;
        rtt_line[pos..pos+2].copy_from_slice(b"ms");
        print_line(&rtt_line[..pos+2], COLOR_TEXT_DIM);
    }
}
