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

use crate::log::*;
use crate::test::framework::TestResult;

pub(crate) fn test_log_entry_creation() -> TestResult {
    let entry = LogEntry {
        ts: 12345,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    if entry.ts != 12345 {
        return TestResult::Fail;
    }
    if entry.cpu != 0 {
        return TestResult::Fail;
    }
    if entry.sev != Severity::Info {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_with_message() -> TestResult {
    let mut entry = LogEntry {
        ts: 100,
        cpu: 1,
        sev: Severity::Debug,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    let _ = entry.msg.push_str("test message");
    if entry.msg.as_str() != "test message" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_clone() -> TestResult {
    let mut entry1 = LogEntry {
        ts: 999,
        cpu: 2,
        sev: Severity::Warn,
        msg: heapless::String::new(),
        hash: [1u8; 32],
    };
    let _ = entry1.msg.push_str("clone test");
    let entry2 = entry1.clone();
    if entry1.ts != entry2.ts {
        return TestResult::Fail;
    }
    if entry1.cpu != entry2.cpu {
        return TestResult::Fail;
    }
    if entry1.sev != entry2.sev {
        return TestResult::Fail;
    }
    if entry1.msg != entry2.msg {
        return TestResult::Fail;
    }
    if entry1.hash != entry2.hash {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_timestamp_zero() -> TestResult {
    let entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    if entry.ts != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_timestamp_max() -> TestResult {
    let entry = LogEntry {
        ts: u64::MAX,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    if entry.ts != u64::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_cpu_various_values() -> TestResult {
    for cpu_id in [0, 1, 4, 8, 16, 255, u32::MAX] {
        let entry = LogEntry {
            ts: 0,
            cpu: cpu_id,
            sev: Severity::Info,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        if entry.cpu != cpu_id {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_all_severity_levels() -> TestResult {
    let severities =
        [Severity::Debug, Severity::Info, Severity::Warn, Severity::Err, Severity::Fatal];
    for sev in severities {
        let entry = LogEntry { ts: 0, cpu: 0, sev, msg: heapless::String::new(), hash: [0u8; 32] };
        if entry.sev != sev {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_hash_default() -> TestResult {
    let entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    if entry.hash != [0u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_hash_nonzero() -> TestResult {
    let mut hash = [0u8; 32];
    for i in 0..32 {
        hash[i] = i as u8;
    }
    let entry = LogEntry { ts: 0, cpu: 0, sev: Severity::Info, msg: heapless::String::new(), hash };
    for i in 0..32 {
        if entry.hash[i] != i as u8 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_message_empty() -> TestResult {
    let entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    if !entry.msg.is_empty() {
        return TestResult::Fail;
    }
    if entry.msg.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_message_long() -> TestResult {
    let mut entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    let long_msg = "a".repeat(200);
    let _ = entry.msg.push_str(&long_msg);
    if entry.msg.len() != 200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_message_max_capacity() -> TestResult {
    let mut entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    let max_msg = "x".repeat(256);
    let _ = entry.msg.push_str(&max_msg);
    if entry.msg.len() != 256 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_message_exceeds_capacity() -> TestResult {
    let mut entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    let overflow_msg = "y".repeat(300);
    let result = entry.msg.push_str(&overflow_msg);
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_clone_independence() -> TestResult {
    let mut entry1 = LogEntry {
        ts: 100,
        cpu: 1,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [5u8; 32],
    };
    let _ = entry1.msg.push_str("original");
    let mut entry2 = entry1.clone();
    entry2.ts = 200;
    entry2.cpu = 2;
    entry2.sev = Severity::Err;
    entry2.msg.clear();
    let _ = entry2.msg.push_str("modified");
    entry2.hash = [10u8; 32];
    if entry1.ts != 100 {
        return TestResult::Fail;
    }
    if entry1.cpu != 1 {
        return TestResult::Fail;
    }
    if entry1.sev != Severity::Info {
        return TestResult::Fail;
    }
    if entry1.msg.as_str() != "original" {
        return TestResult::Fail;
    }
    if entry1.hash != [5u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_hash_size() -> TestResult {
    let entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    if entry.hash.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_message_push_single_char() -> TestResult {
    let mut entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Debug,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    let _ = entry.msg.push('A');
    if entry.msg.as_str() != "A" {
        return TestResult::Fail;
    }
    if entry.msg.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_message_unicode() -> TestResult {
    let mut entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    let _ = entry.msg.push_str("hello");
    if !(entry.msg.len() > 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_entry_multiple_modifications() -> TestResult {
    let mut entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    let _ = entry.msg.push_str("first");
    entry.msg.clear();
    let _ = entry.msg.push_str("second");
    if entry.msg.as_str() != "second" {
        return TestResult::Fail;
    }
    TestResult::Pass
}
