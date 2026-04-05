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
use crate::test::framework::TestResult;

pub fn test_daemon_state_new() -> TestResult {
    let state = DaemonState::new();
    if !state.node.is_none() {
        return TestResult::Fail;
    }
    if state.running {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn test_daemon_state_new_staking() -> TestResult {
    let state = DaemonState::new();
    if !state.staking.stake.amount.is_zero() {
        return TestResult::Fail;
    }
    if state.staking.current_epoch != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn test_daemon_state_new_p2p() -> TestResult {
    let state = DaemonState::new();
    if state.p2p.status != ConnectionStatus::Disconnected {
        return TestResult::Fail;
    }
    if state.p2p.peer_count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn test_daemon_state_new_privacy() -> TestResult {
    let state = DaemonState::new();
    if state.privacy.identity_count != 0 {
        return TestResult::Fail;
    }
    if !state.privacy.stealth_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}
