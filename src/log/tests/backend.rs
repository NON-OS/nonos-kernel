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

pub(crate) fn test_ram_buf_size_constant() -> TestResult {
    if RAM_BUF_SIZE != 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_new() -> TestResult {
    let backend = RamBufferBackend::new();
    if backend.entry_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_write_single() -> TestResult {
    let mut backend = RamBufferBackend::new();
    let entry = LogEntry {
        ts: 12345,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    backend.write(&entry);
    if backend.entry_count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_write_multiple() -> TestResult {
    let mut backend = RamBufferBackend::new();
    for i in 0..10 {
        let entry = LogEntry {
            ts: i as u64,
            cpu: 0,
            sev: Severity::Info,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        backend.write(&entry);
    }
    if backend.entry_count() != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_get_entries_empty() -> TestResult {
    let backend = RamBufferBackend::new();
    let entries = backend.get_entries();
    if !entries.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_get_entries_single() -> TestResult {
    let mut backend = RamBufferBackend::new();
    let mut entry = LogEntry {
        ts: 100,
        cpu: 1,
        sev: Severity::Warn,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    let _ = entry.msg.push_str("test");
    backend.write(&entry);
    let entries = backend.get_entries();
    if entries.len() != 1 {
        return TestResult::Fail;
    }
    if entries[0].ts != 100 {
        return TestResult::Fail;
    }
    if entries[0].cpu != 1 {
        return TestResult::Fail;
    }
    if entries[0].sev != Severity::Warn {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_get_entries_preserves_order() -> TestResult {
    let mut backend = RamBufferBackend::new();
    for i in 0..5 {
        let entry = LogEntry {
            ts: i as u64,
            cpu: 0,
            sev: Severity::Info,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        backend.write(&entry);
    }
    let entries = backend.get_entries();
    for i in 0..5 {
        if entries[i].ts != i as u64 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_get_recent_empty() -> TestResult {
    let backend = RamBufferBackend::new();
    let recent = backend.get_recent(5);
    if !recent.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_get_recent_single() -> TestResult {
    let mut backend = RamBufferBackend::new();
    let entry = LogEntry {
        ts: 50,
        cpu: 0,
        sev: Severity::Debug,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    backend.write(&entry);
    let recent = backend.get_recent(1);
    if recent.len() != 1 {
        return TestResult::Fail;
    }
    if recent[0].ts != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_get_recent_less_than_requested() -> TestResult {
    let mut backend = RamBufferBackend::new();
    for i in 0..3 {
        let entry = LogEntry {
            ts: i as u64,
            cpu: 0,
            sev: Severity::Info,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        backend.write(&entry);
    }
    let recent = backend.get_recent(10);
    if recent.len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_get_recent_exact_count() -> TestResult {
    let mut backend = RamBufferBackend::new();
    for i in 0..5 {
        let entry = LogEntry {
            ts: i as u64,
            cpu: 0,
            sev: Severity::Info,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        backend.write(&entry);
    }
    let recent = backend.get_recent(3);
    if recent.len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_get_recent_returns_newest() -> TestResult {
    let mut backend = RamBufferBackend::new();
    for i in 0..10 {
        let entry = LogEntry {
            ts: i as u64,
            cpu: 0,
            sev: Severity::Info,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        backend.write(&entry);
    }
    let recent = backend.get_recent(3);
    if recent[0].ts != 7 {
        return TestResult::Fail;
    }
    if recent[1].ts != 8 {
        return TestResult::Fail;
    }
    if recent[2].ts != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_clear() -> TestResult {
    let mut backend = RamBufferBackend::new();
    for i in 0..5 {
        let entry = LogEntry {
            ts: i as u64,
            cpu: 0,
            sev: Severity::Info,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        backend.write(&entry);
    }
    if backend.entry_count() != 5 {
        return TestResult::Fail;
    }
    backend.clear();
    if backend.entry_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_clear_then_write() -> TestResult {
    let mut backend = RamBufferBackend::new();
    for i in 0..3 {
        let entry = LogEntry {
            ts: i as u64,
            cpu: 0,
            sev: Severity::Info,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        backend.write(&entry);
    }
    backend.clear();
    let entry = LogEntry {
        ts: 100,
        cpu: 0,
        sev: Severity::Debug,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    backend.write(&entry);
    if backend.entry_count() != 1 {
        return TestResult::Fail;
    }
    let entries = backend.get_entries();
    if entries[0].ts != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_entry_count_zero() -> TestResult {
    let backend = RamBufferBackend::new();
    if backend.entry_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_circular_buffer_wrap() -> TestResult {
    let mut backend = RamBufferBackend::new();
    for i in 0..RAM_BUF_SIZE {
        let entry = LogEntry {
            ts: i as u64,
            cpu: 0,
            sev: Severity::Info,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        backend.write(&entry);
    }
    if backend.entry_count() != RAM_BUF_SIZE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_circular_buffer_overflow() -> TestResult {
    let mut backend = RamBufferBackend::new();
    for i in 0..(RAM_BUF_SIZE + 10) {
        let entry = LogEntry {
            ts: i as u64,
            cpu: 0,
            sev: Severity::Info,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        backend.write(&entry);
    }
    if backend.entry_count() != RAM_BUF_SIZE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_preserves_entry_data() -> TestResult {
    let mut backend = RamBufferBackend::new();
    let mut entry = LogEntry {
        ts: 999,
        cpu: 7,
        sev: Severity::Fatal,
        msg: heapless::String::new(),
        hash: [42u8; 32],
    };
    let _ = entry.msg.push_str("preserved");
    backend.write(&entry);
    let entries = backend.get_entries();
    if entries[0].ts != 999 {
        return TestResult::Fail;
    }
    if entries[0].cpu != 7 {
        return TestResult::Fail;
    }
    if entries[0].sev != Severity::Fatal {
        return TestResult::Fail;
    }
    if entries[0].msg.as_str() != "preserved" {
        return TestResult::Fail;
    }
    if entries[0].hash != [42u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_const_new() -> TestResult {
    const _BACKEND: RamBufferBackend = RamBufferBackend::new();
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_get_recent_zero() -> TestResult {
    let mut backend = RamBufferBackend::new();
    for i in 0..5 {
        let entry = LogEntry {
            ts: i as u64,
            cpu: 0,
            sev: Severity::Info,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        backend.write(&entry);
    }
    let recent = backend.get_recent(0);
    if !recent.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_write_different_severities() -> TestResult {
    let mut backend = RamBufferBackend::new();
    let severities =
        [Severity::Debug, Severity::Info, Severity::Warn, Severity::Err, Severity::Fatal];
    for (i, sev) in severities.iter().enumerate() {
        let entry = LogEntry {
            ts: i as u64,
            cpu: 0,
            sev: *sev,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        backend.write(&entry);
    }
    let entries = backend.get_entries();
    if entries[0].sev != Severity::Debug {
        return TestResult::Fail;
    }
    if entries[1].sev != Severity::Info {
        return TestResult::Fail;
    }
    if entries[2].sev != Severity::Warn {
        return TestResult::Fail;
    }
    if entries[3].sev != Severity::Err {
        return TestResult::Fail;
    }
    if entries[4].sev != Severity::Fatal {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_write_different_cpus() -> TestResult {
    let mut backend = RamBufferBackend::new();
    for cpu in 0..8 {
        let entry = LogEntry {
            ts: 0,
            cpu,
            sev: Severity::Info,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        backend.write(&entry);
    }
    let entries = backend.get_entries();
    for i in 0..8 {
        if entries[i].cpu != i as u32 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_get_entries_after_clear() -> TestResult {
    let mut backend = RamBufferBackend::new();
    for i in 0..5 {
        let entry = LogEntry {
            ts: i as u64,
            cpu: 0,
            sev: Severity::Info,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        backend.write(&entry);
    }
    backend.clear();
    let entries = backend.get_entries();
    if !entries.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_get_recent_after_clear() -> TestResult {
    let mut backend = RamBufferBackend::new();
    for i in 0..5 {
        let entry = LogEntry {
            ts: i as u64,
            cpu: 0,
            sev: Severity::Info,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        backend.write(&entry);
    }
    backend.clear();
    let recent = backend.get_recent(10);
    if !recent.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_backend_trait_object_safety() -> TestResult {
    let mut backend = RamBufferBackend::new();
    let entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    let backend_ref: &mut dyn LogBackend = &mut backend;
    backend_ref.write(&entry);
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_write_message_preserved() -> TestResult {
    let mut backend = RamBufferBackend::new();
    let mut entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    let _ = entry.msg.push_str("hello world");
    backend.write(&entry);
    let entries = backend.get_entries();
    if entries[0].msg.as_str() != "hello world" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_multiple_clears() -> TestResult {
    let mut backend = RamBufferBackend::new();
    for _ in 0..3 {
        for i in 0..5 {
            let entry = LogEntry {
                ts: i as u64,
                cpu: 0,
                sev: Severity::Info,
                msg: heapless::String::new(),
                hash: [0u8; 32],
            };
            backend.write(&entry);
        }
        backend.clear();
        if backend.entry_count() != 0 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_ram_buffer_backend_hash_preserved() -> TestResult {
    let mut backend = RamBufferBackend::new();
    let mut hash = [0u8; 32];
    for i in 0..32 {
        hash[i] = (i * 3) as u8;
    }
    let entry = LogEntry { ts: 0, cpu: 0, sev: Severity::Info, msg: heapless::String::new(), hash };
    backend.write(&entry);
    let entries = backend.get_entries();
    for i in 0..32 {
        if entries[0].hash[i] != (i * 3) as u8 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
