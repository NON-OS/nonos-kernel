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
    COLOR_ACCENT, COLOR_GREEN, COLOR_RED, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE,
};
use crate::shell::output::print_line;
use crate::daemon::get_daemon_state;

use super::format::{print_prefixed, print_number_line};

pub fn cmd_identity_list() {
    print_line(b"ZK Identities", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);

    let state = get_daemon_state();
    let privacy = &state.privacy;

    print_number_line(b"Total: ", privacy.identity_count as u32, b"");
    print_number_line(b"Active: ", privacy.active_count() as u32, b"");

    if privacy.identity_count > 0 {
        print_line(b"", COLOR_TEXT);
        for i in 0..privacy.identity_count {
            let identity = &privacy.identities[i];
            let short = identity.short_id();
            let color = if i == privacy.active_identity {
                COLOR_GREEN
            } else if identity.active {
                COLOR_TEXT
            } else {
                COLOR_TEXT_DIM
            };

            let mut line = [0u8; 32];
            line[0] = b'[';
            line[1] = b'0' + (i % 10) as u8;
            line[2] = b']';
            line[3] = b' ';
            if i == privacy.active_identity {
                line[4..7].copy_from_slice(b">> ");
            } else {
                line[4..7].copy_from_slice(b"   ");
            }
            line[7..23].copy_from_slice(&short);
            print_line(&line[..23], color);
        }
    }
}

pub fn cmd_identity_new() {
    let mut state = get_daemon_state();
    let current_epoch = state.staking.current_epoch;

    match state.privacy.create_identity(current_epoch) {
        Some(idx) => {
            print_line(b"Identity created", COLOR_GREEN);
            let identity = &state.privacy.identities[idx];
            let short = identity.short_id();
            print_prefixed(b"ID: ", &short);
        }
        None => {
            print_line(b"Max identities reached", COLOR_RED);
        }
    }
}

pub fn cmd_node_help() {
    print_line(b"NONOS Node Commands", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"Node:", COLOR_ACCENT);
    print_line(b"  node            Node status", COLOR_TEXT);
    print_line(b"  node-init       Initialize node", COLOR_TEXT);
    print_line(b"  node-start      Start node", COLOR_TEXT);
    print_line(b"  node-stop       Stop node", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);
    print_line(b"Staking:", COLOR_ACCENT);
    print_line(b"  stake           Staking status", COLOR_TEXT);
    print_line(b"  stake-deposit   Deposit NOX", COLOR_TEXT);
    print_line(b"  rewards-claim   Claim rewards", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);
    print_line(b"Network:", COLOR_ACCENT);
    print_line(b"  peers           List peers", COLOR_TEXT);
    print_line(b"  mixer           Mixer status", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);
    print_line(b"Privacy:", COLOR_ACCENT);
    print_line(b"  identity        List identities", COLOR_TEXT);
    print_line(b"  identity-new    Create identity", COLOR_TEXT);
}
