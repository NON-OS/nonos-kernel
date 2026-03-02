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
    COLOR_ACCENT, COLOR_GREEN, COLOR_RED, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW,
};
use crate::shell::output::print_line;
use crate::daemon::get_daemon_state;
use crate::daemon::types::ConnectionStatus;

use super::format::{print_prefixed, print_number_line, print_bytes};

pub fn cmd_peers_list() {
    print_line(b"Connected Peers", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);

    let state = get_daemon_state();
    let p2p = &state.p2p;

    let status_msg = match p2p.status {
        ConnectionStatus::Connected => (b"Network: CONNECTED" as &[u8], COLOR_GREEN),
        ConnectionStatus::Connecting => (b"Network: CONNECTING" as &[u8], COLOR_YELLOW),
        ConnectionStatus::Bootstrapping => (b"Network: BOOTSTRAPPING" as &[u8], COLOR_YELLOW),
        ConnectionStatus::Disconnected => (b"Network: DISCONNECTED" as &[u8], COLOR_TEXT_DIM),
        ConnectionStatus::Error => (b"Network: ERROR" as &[u8], COLOR_RED),
    };
    print_line(status_msg.0, status_msg.1);

    print_line(b"", COLOR_TEXT);
    print_number_line(b"Total Peers: ", p2p.peer_count as u32, b"");
    print_number_line(b"Connected: ", p2p.connected_peers() as u32, b"");

    if p2p.peer_count > 0 {
        print_line(b"", COLOR_TEXT);
        print_line(b"Peers:", COLOR_ACCENT);
        for i in 0..p2p.peer_count.min(10) {
            let peer = &p2p.peers[i];
            let short = peer.id.short_id();
            print_prefixed(b"  ", &short);
        }
        if p2p.peer_count > 10 {
            print_number_line(b"  ... and ", (p2p.peer_count - 10) as u32, b" more");
        }
    }
}

pub fn cmd_mixer_status() {
    print_line(b"Cache Mixer", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);

    let state = get_daemon_state();
    let p2p = &state.p2p;

    if p2p.mixing_enabled {
        print_line(b"Status: ENABLED", COLOR_GREEN);
    } else {
        print_line(b"Status: DISABLED", COLOR_TEXT_DIM);
    }

    print_line(b"", COLOR_TEXT);
    print_number_line(b"Cache Size: ", p2p.cache_size_mb, b" MB");

    print_line(b"", COLOR_TEXT);
    print_line(b"Traffic:", COLOR_ACCENT);
    print_bytes(b"  Sent: ", p2p.total_bytes_sent);
    print_bytes(b"  Received: ", p2p.total_bytes_received);
}
