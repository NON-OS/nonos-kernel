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

use crate::daemon::*;

#[test]
fn test_daemon_state_new() {
    let state = DaemonState::new();
    assert!(state.node.is_none());
    assert!(!state.running);
}

#[test]
fn test_daemon_state_new_staking() {
    let state = DaemonState::new();
    assert!(state.staking.stake.amount.is_zero());
    assert_eq!(state.staking.current_epoch, 0);
}

#[test]
fn test_daemon_state_new_p2p() {
    let state = DaemonState::new();
    assert_eq!(state.p2p.status, ConnectionStatus::Disconnected);
    assert_eq!(state.p2p.peer_count, 0);
}

#[test]
fn test_daemon_state_new_privacy() {
    let state = DaemonState::new();
    assert_eq!(state.privacy.identity_count, 0);
    assert!(state.privacy.stealth_enabled);
}
