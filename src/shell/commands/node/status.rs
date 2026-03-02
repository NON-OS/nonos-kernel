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
use crate::daemon::{get_daemon_state, init_daemon};
use crate::daemon::types::NodeStatus;

use super::format::{print_prefixed, print_tier, print_number_line};

pub fn cmd_node_status() {
    print_line(b"NONOS Node", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);

    let state = get_daemon_state();

    if let Some(ref node) = state.node {
        let status_msg = match node.status {
            NodeStatus::Running => (b"Status: RUNNING" as &[u8], COLOR_GREEN),
            NodeStatus::Starting => (b"Status: STARTING" as &[u8], COLOR_YELLOW),
            NodeStatus::Syncing => (b"Status: SYNCING" as &[u8], COLOR_YELLOW),
            NodeStatus::Stopped => (b"Status: STOPPED" as &[u8], COLOR_TEXT_DIM),
            NodeStatus::Error => (b"Status: ERROR" as &[u8], COLOR_RED),
        };
        print_line(status_msg.0, status_msg.1);
        print_line(b"", COLOR_TEXT);

        print_line(b"Node ID:", COLOR_ACCENT);
        let short = node.id.short_id();
        print_prefixed(b"  ", &short);

        print_line(b"", COLOR_TEXT);
        print_line(b"Nickname:", COLOR_ACCENT);
        print_prefixed(b"  ", node.get_nickname());

        print_line(b"", COLOR_TEXT);
        print_tier(b"Tier: ", node.tier);

        print_line(b"", COLOR_TEXT);
        print_line(b"Quality Score:", COLOR_ACCENT);
        print_number_line(b"  Total: ", node.quality.total() as u32, b"%");

        print_line(b"", COLOR_TEXT);
        print_line(b"Stats:", COLOR_ACCENT);
        print_number_line(b"  Connections: ", node.active_connections, b"");
        print_number_line(b"  Requests: ", node.total_requests as u32, b"");
        print_number_line(b"  Success Rate: ", node.success_rate() as u32, b"%");
    } else {
        print_line(b"Node not initialized", COLOR_YELLOW);
        print_line(b"", COLOR_TEXT);
        print_line(b"Run 'node-init' to initialize", COLOR_TEXT_DIM);
    }
}

pub fn cmd_node_init() {
    print_line(b"Initializing NONOS Node...", COLOR_TEXT_WHITE);

    match init_daemon() {
        Ok(()) => {
            print_line(b"Node initialized", COLOR_GREEN);
            let state = get_daemon_state();
            if let Some(ref node) = state.node {
                print_line(b"", COLOR_TEXT);
                print_line(b"Node ID:", COLOR_ACCENT);
                let short = node.id.short_id();
                print_prefixed(b"  ", &short);
            }
        }
        Err(e) => {
            let msg = e.as_bytes();
            print_prefixed(b"Error: ", msg);
        }
    }
}

pub fn cmd_node_start() {
    let mut state = get_daemon_state();

    if state.node.is_none() {
        drop(state);
        print_line(b"Node not initialized", COLOR_RED);
        print_line(b"Run 'node-init' first", COLOR_TEXT_DIM);
        return;
    }

    if let Some(ref mut node) = state.node {
        if node.status == NodeStatus::Running {
            print_line(b"Node already running", COLOR_YELLOW);
            return;
        }

        node.start();
        print_line(b"Node starting...", COLOR_GREEN);
    }
}

pub fn cmd_node_stop() {
    let mut state = get_daemon_state();

    if let Some(ref mut node) = state.node {
        if node.status == NodeStatus::Stopped {
            print_line(b"Node already stopped", COLOR_YELLOW);
            return;
        }

        node.stop();
        print_line(b"Node stopped", COLOR_GREEN);
    } else {
        print_line(b"Node not initialized", COLOR_RED);
    }
}
