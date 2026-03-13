// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::ring::LogRingBuffer;
use crate::log::types::LogLevel;

#[test]
fn test_ring_buffer_push() {
    let mut buf: LogRingBuffer<4> = LogRingBuffer::new();
    assert!(buf.is_empty());

    buf.push_message(1, LogLevel::Info, 0, "test1");
    assert_eq!(buf.len(), 1);

    buf.push_message(2, LogLevel::Info, 0, "test2");
    buf.push_message(3, LogLevel::Info, 0, "test3");
    buf.push_message(4, LogLevel::Info, 0, "test4");
    assert!(buf.is_full());
    assert_eq!(buf.overflow_count(), 0);

    buf.push_message(5, LogLevel::Info, 0, "test5");
    assert_eq!(buf.len(), 4);
    assert_eq!(buf.overflow_count(), 1);

    let first = buf.get(0).unwrap();
    assert_eq!(first.tick, 2);
}

#[test]
fn test_ring_buffer_iter() {
    let mut buf: LogRingBuffer<4> = LogRingBuffer::new();
    buf.push_message(1, LogLevel::Info, 0, "a");
    buf.push_message(2, LogLevel::Warn, 0, "b");
    buf.push_message(3, LogLevel::Error, 0, "c");

    let ticks: Vec<u64> = buf.iter().map(|e| e.tick).collect();
    assert_eq!(ticks, vec![1, 2, 3]);
}
