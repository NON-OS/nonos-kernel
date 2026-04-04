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
fn test_ram_buf_size_constant() {
    assert_eq!(RAM_BUF_SIZE, 1024);
}

#[test]
fn test_ram_buffer_backend_new() {
    let backend = RamBufferBackend::new();
    assert_eq!(backend.entry_count(), 0);
}

#[test]
fn test_ram_buffer_backend_write_single() {
    let mut backend = RamBufferBackend::new();
    let entry = LogEntry {
        ts: 12345,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash: [0u8; 32],
    };
    backend.write(&entry);
    assert_eq!(backend.entry_count(), 1);
}

#[test]
fn test_ram_buffer_backend_write_multiple() {
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
    assert_eq!(backend.entry_count(), 10);
}

#[test]
fn test_ram_buffer_backend_get_entries_empty() {
    let backend = RamBufferBackend::new();
    let entries = backend.get_entries();
    assert!(entries.is_empty());
}

#[test]
fn test_ram_buffer_backend_get_entries_single() {
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
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].ts, 100);
    assert_eq!(entries[0].cpu, 1);
    assert_eq!(entries[0].sev, Severity::Warn);
}

#[test]
fn test_ram_buffer_backend_get_entries_preserves_order() {
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
        assert_eq!(entries[i].ts, i as u64);
    }
}

#[test]
fn test_ram_buffer_backend_get_recent_empty() {
    let backend = RamBufferBackend::new();
    let recent = backend.get_recent(5);
    assert!(recent.is_empty());
}

#[test]
fn test_ram_buffer_backend_get_recent_single() {
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
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].ts, 50);
}

#[test]
fn test_ram_buffer_backend_get_recent_less_than_requested() {
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
    assert_eq!(recent.len(), 3);
}

#[test]
fn test_ram_buffer_backend_get_recent_exact_count() {
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
    assert_eq!(recent.len(), 3);
}

#[test]
fn test_ram_buffer_backend_get_recent_returns_newest() {
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
    assert_eq!(recent[0].ts, 7);
    assert_eq!(recent[1].ts, 8);
    assert_eq!(recent[2].ts, 9);
}

#[test]
fn test_ram_buffer_backend_clear() {
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
    assert_eq!(backend.entry_count(), 5);
    backend.clear();
    assert_eq!(backend.entry_count(), 0);
}

#[test]
fn test_ram_buffer_backend_clear_then_write() {
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
    assert_eq!(backend.entry_count(), 1);
    let entries = backend.get_entries();
    assert_eq!(entries[0].ts, 100);
}

#[test]
fn test_ram_buffer_backend_entry_count_zero() {
    let backend = RamBufferBackend::new();
    assert_eq!(backend.entry_count(), 0);
}

#[test]
fn test_ram_buffer_backend_circular_buffer_wrap() {
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
    assert_eq!(backend.entry_count(), RAM_BUF_SIZE);
}

#[test]
fn test_ram_buffer_backend_circular_buffer_overflow() {
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
    assert_eq!(backend.entry_count(), RAM_BUF_SIZE);
}

#[test]
fn test_ram_buffer_backend_preserves_entry_data() {
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
    assert_eq!(entries[0].ts, 999);
    assert_eq!(entries[0].cpu, 7);
    assert_eq!(entries[0].sev, Severity::Fatal);
    assert_eq!(entries[0].msg.as_str(), "preserved");
    assert_eq!(entries[0].hash, [42u8; 32]);
}

#[test]
fn test_ram_buffer_backend_const_new() {
    const _BACKEND: RamBufferBackend = RamBufferBackend::new();
}

#[test]
fn test_ram_buffer_backend_get_recent_zero() {
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
    assert!(recent.is_empty());
}

#[test]
fn test_ram_buffer_backend_write_different_severities() {
    let mut backend = RamBufferBackend::new();
    let severities = [
        Severity::Debug,
        Severity::Info,
        Severity::Warn,
        Severity::Err,
        Severity::Fatal,
    ];
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
    assert_eq!(entries[0].sev, Severity::Debug);
    assert_eq!(entries[1].sev, Severity::Info);
    assert_eq!(entries[2].sev, Severity::Warn);
    assert_eq!(entries[3].sev, Severity::Err);
    assert_eq!(entries[4].sev, Severity::Fatal);
}

#[test]
fn test_ram_buffer_backend_write_different_cpus() {
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
        assert_eq!(entries[i].cpu, i as u32);
    }
}

#[test]
fn test_ram_buffer_backend_get_entries_after_clear() {
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
    assert!(entries.is_empty());
}

#[test]
fn test_ram_buffer_backend_get_recent_after_clear() {
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
    assert!(recent.is_empty());
}

#[test]
fn test_log_backend_trait_object_safety() {
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
}

#[test]
fn test_ram_buffer_backend_write_message_preserved() {
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
    assert_eq!(entries[0].msg.as_str(), "hello world");
}

#[test]
fn test_ram_buffer_backend_multiple_clears() {
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
        assert_eq!(backend.entry_count(), 0);
    }
}

#[test]
fn test_ram_buffer_backend_hash_preserved() {
    let mut backend = RamBufferBackend::new();
    let mut hash = [0u8; 32];
    for i in 0..32 {
        hash[i] = (i * 3) as u8;
    }
    let entry = LogEntry {
        ts: 0,
        cpu: 0,
        sev: Severity::Info,
        msg: heapless::String::new(),
        hash,
    };
    backend.write(&entry);
    let entries = backend.get_entries();
    for i in 0..32 {
        assert_eq!(entries[0].hash[i], (i * 3) as u8);
    }
}
