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

#[test]
fn test_log_entry_creation() {
    let entry = LogEntry {
        ts: 12345,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    assert_eq!(entry.ts, 12345);
    assert_eq!(entry.cpu, 0);
    assert_eq!(entry.sev, Severity::Info);
}

#[test]
fn test_log_entry_with_message() {
    let mut entry = LogEntry {
        ts: 100,
        cpu: 1,
        sev: Severity::Debug,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    let _ = entry.msg.push_str("test message");
    assert_eq!(entry.msg.as_str(), "test message");
}

#[test]
fn test_log_entry_clone() {
    let mut entry1 = LogEntry {
        ts: 999,
        cpu: 2,
        sev: Severity::Warn,
        msg: heapless::String::new(),
        hash: [1u8; 32],
    };
    let _ = entry1.msg.push_str("clone test");
    let entry2 = entry1.clone();
    assert_eq!(entry1.ts, entry2.ts);
    assert_eq!(entry1.cpu, entry2.cpu);
    assert_eq!(entry1.sev, entry2.sev);
    assert_eq!(entry1.msg, entry2.msg);
    assert_eq!(entry1.hash, entry2.hash);
}

#[test]
fn test_log_entry_timestamp_zero() {
    let entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    assert_eq!(entry.ts, 0);
}

#[test]
fn test_log_entry_timestamp_max() {
    let entry = LogEntry {
        ts: u64::MAX,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    assert_eq!(entry.ts, u64::MAX);
}

#[test]
fn test_log_entry_cpu_various_values() {
    for cpu_id in [0, 1, 4, 8, 16, 255, u32::MAX] {
        let entry = LogEntry {
            ts: 0,
            cpu: cpu_id,
            sev: Severity::Info,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        assert_eq!(entry.cpu, cpu_id);
    }
}

#[test]
fn test_log_entry_all_severity_levels() {
    let severities = [
        Severity::Debug,
        Severity::Info,
        Severity::Warn,
        Severity::Err,
        Severity::Fatal,
    ];
    for sev in severities {
        let entry = LogEntry {
            ts: 0,
            cpu: 0,
            sev,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        assert_eq!(entry.sev, sev);
    }
}

#[test]
fn test_log_entry_hash_default() {
    let entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    assert_eq!(entry.hash, [0u8; 32]);
}

#[test]
fn test_log_entry_hash_nonzero() {
    let mut hash = [0u8; 32];
    for i in 0..32 {
        hash[i] = i as u8;
    }
    let entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash,
    };
    for i in 0..32 {
        assert_eq!(entry.hash[i], i as u8);
    }
}

#[test]
fn test_log_entry_message_empty() {
    let entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    assert!(entry.msg.is_empty());
    assert_eq!(entry.msg.len(), 0);
}

#[test]
fn test_log_entry_message_long() {
    let mut entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    let long_msg = "a".repeat(200);
    let _ = entry.msg.push_str(&long_msg);
    assert_eq!(entry.msg.len(), 200);
}

#[test]
fn test_log_entry_message_max_capacity() {
    let mut entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    let max_msg = "x".repeat(256);
    let _ = entry.msg.push_str(&max_msg);
    assert_eq!(entry.msg.len(), 256);
}

#[test]
fn test_log_entry_message_exceeds_capacity() {
    let mut entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    let overflow_msg = "y".repeat(300);
    let result = entry.msg.push_str(&overflow_msg);
    assert!(result.is_err());
}

#[test]
fn test_log_entry_clone_independence() {
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
    assert_eq!(entry1.ts, 100);
    assert_eq!(entry1.cpu, 1);
    assert_eq!(entry1.sev, Severity::Info);
    assert_eq!(entry1.msg.as_str(), "original");
    assert_eq!(entry1.hash, [5u8; 32]);
}

#[test]
fn test_log_entry_hash_size() {
    let entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    assert_eq!(entry.hash.len(), 32);
}

#[test]
fn test_log_entry_message_push_single_char() {
    let mut entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Debug,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    let _ = entry.msg.push('A');
    assert_eq!(entry.msg.as_str(), "A");
    assert_eq!(entry.msg.len(), 1);
}

#[test]
fn test_log_entry_message_unicode() {
    let mut entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    let _ = entry.msg.push_str("hello");
    assert!(entry.msg.len() > 0);
}

#[test]
fn test_log_entry_multiple_modifications() {
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
    assert_eq!(entry.msg.as_str(), "second");
}
