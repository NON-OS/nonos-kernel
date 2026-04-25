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

pub(crate) fn test_node_id_from_bytes() -> TestResult {
    let bytes = [0x42u8; 32];
    let id = NodeId::from_bytes(bytes);
    if id.0 != bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_id_as_bytes() -> TestResult {
    let bytes = [0x42u8; 32];
    let id = NodeId::from_bytes(bytes);
    if id.as_bytes() != &bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_id_short_id_prefix() -> TestResult {
    let bytes = [0u8; 32];
    let id = NodeId::from_bytes(bytes);
    let short = id.short_id();
    if &short[..5] != b"nxnd_" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_id_short_id_length() -> TestResult {
    let bytes = [0xABu8; 32];
    let id = NodeId::from_bytes(bytes);
    let short = id.short_id();
    if short.len() != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_id_short_id_hex_encoding() -> TestResult {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xAB;
    bytes[1] = 0xCD;
    let id = NodeId::from_bytes(bytes);
    let short = id.short_id();
    if &short[5..9] != b"abcd" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_generate_status() -> TestResult {
    let info = NodeInfo::generate();
    if info.status != NodeStatus::Stopped {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_generate_tier() -> TestResult {
    let info = NodeInfo::generate();
    if info.tier != NodeTier::Bronze {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_generate_quality() -> TestResult {
    let info = NodeInfo::generate();
    if info.quality.uptime != 0 {
        return TestResult::Fail;
    }
    if info.quality.success_rate != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_generate_staked() -> TestResult {
    let info = NodeInfo::generate();
    if !info.staked.is_zero() {
        return TestResult::Fail;
    }
    if !info.pending_rewards.is_zero() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_generate_counters() -> TestResult {
    let info = NodeInfo::generate();
    if info.streak != 0 {
        return TestResult::Fail;
    }
    if info.uptime_secs != 0 {
        return TestResult::Fail;
    }
    if info.active_connections != 0 {
        return TestResult::Fail;
    }
    if info.total_requests != 0 {
        return TestResult::Fail;
    }
    if info.successful_requests != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_generate_nickname() -> TestResult {
    let info = NodeInfo::generate();
    if &info.nickname[..11] != b"nonos-node-" {
        return TestResult::Fail;
    }
    if info.nickname_len != 19 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_set_nickname() -> TestResult {
    let mut info = NodeInfo::generate();
    info.set_nickname(b"my-custom-node");
    if info.get_nickname() != b"my-custom-node" {
        return TestResult::Fail;
    }
    if info.nickname_len != 14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_set_nickname_truncates() -> TestResult {
    let mut info = NodeInfo::generate();
    let long_name = [b'x'; 64];
    info.set_nickname(&long_name);
    if info.nickname_len != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_set_nickname_empty() -> TestResult {
    let mut info = NodeInfo::generate();
    info.set_nickname(b"");
    if info.get_nickname() != b"" {
        return TestResult::Fail;
    }
    if info.nickname_len != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_success_rate_zero_requests() -> TestResult {
    let info = NodeInfo::generate();
    if info.success_rate() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_success_rate_all_successful() -> TestResult {
    let mut info = NodeInfo::generate();
    info.total_requests = 100;
    info.successful_requests = 100;
    if info.success_rate() != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_success_rate_partial() -> TestResult {
    let mut info = NodeInfo::generate();
    info.total_requests = 100;
    info.successful_requests = 75;
    if info.success_rate() != 75 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_success_rate_none() -> TestResult {
    let mut info = NodeInfo::generate();
    info.total_requests = 100;
    info.successful_requests = 0;
    if info.success_rate() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_update_quality_success_rate() -> TestResult {
    let mut info = NodeInfo::generate();
    info.total_requests = 100;
    info.successful_requests = 80;
    info.update_quality();
    if info.quality.success_rate != 80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_update_quality_uptime_full_day() -> TestResult {
    let mut info = NodeInfo::generate();
    info.uptime_secs = 86400;
    info.update_quality();
    if info.quality.uptime != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_update_quality_uptime_partial() -> TestResult {
    let mut info = NodeInfo::generate();
    info.uptime_secs = 43200;
    info.update_quality();
    if info.quality.uptime != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_update_quality_uptime_more_than_day() -> TestResult {
    let mut info = NodeInfo::generate();
    info.uptime_secs = 172800;
    info.update_quality();
    if info.quality.uptime != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_start() -> TestResult {
    let mut info = NodeInfo::generate();
    if info.status != NodeStatus::Stopped {
        return TestResult::Fail;
    }
    info.start();
    if info.status != NodeStatus::Starting {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_stop() -> TestResult {
    let mut info = NodeInfo::generate();
    info.start();
    info.stop();
    if info.status != NodeStatus::Stopped {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_default() -> TestResult {
    let info = NodeInfo::default();
    if info.status != NodeStatus::Stopped {
        return TestResult::Fail;
    }
    if info.tier != NodeTier::Bronze {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_info_clone() -> TestResult {
    let info = NodeInfo::generate();
    let cloned = info.clone();
    if info.status != cloned.status {
        return TestResult::Fail;
    }
    if info.tier != cloned.tier {
        return TestResult::Fail;
    }
    if info.nickname_len != cloned.nickname_len {
        return TestResult::Fail;
    }
    TestResult::Pass
}
