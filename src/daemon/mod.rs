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

//! NONOS Daemon - Native node, staking, and P2P functionality.
//!
//! This module provides the full NONOS ecosystem native to the OS:
//! - Node identity and management
//! - NOX token staking and rewards
//! - P2P cache mixing network
//! - Privacy features (stealth, ZK identity)

pub mod types;
pub mod node;
pub mod staking;
pub mod p2p;
pub mod privacy;
pub mod rewards;

pub use types::*;
pub use node::*;
pub use staking::*;
pub use p2p::*;
pub use privacy::*;
pub use rewards::*;

use spin::Mutex;

static DAEMON_STATE: Mutex<DaemonState> = Mutex::new(DaemonState::new());

pub struct DaemonState {
    pub node: Option<NodeInfo>,
    pub staking: StakingState,
    pub p2p: P2PState,
    pub privacy: PrivacyState,
    pub running: bool,
}

impl DaemonState {
    pub const fn new() -> Self {
        Self {
            node: None,
            staking: StakingState::new(),
            p2p: P2PState::new(),
            privacy: PrivacyState::new(),
            running: false,
        }
    }
}

pub fn get_daemon_state() -> spin::MutexGuard<'static, DaemonState> {
    DAEMON_STATE.lock()
}

pub fn init_daemon() -> Result<(), &'static str> {
    let mut state = DAEMON_STATE.lock();

    if state.running {
        return Err("Daemon already running");
    }

    state.running = true;
    state.node = Some(NodeInfo::generate());

    Ok(())
}

pub fn stop_daemon() {
    let mut state = DAEMON_STATE.lock();
    state.running = false;
}
