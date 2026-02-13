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

use crate::log::types::{CompactLogEntry, LogEntry, LogLevel};

pub const DEFAULT_RING_CAPACITY: usize = 256;
/// Ring buffer for storing log entries
pub struct LogRingBuffer<const N: usize = DEFAULT_RING_CAPACITY> {
    entries: [CompactLogEntry; N],
    head: usize,
    tail: usize,
    count: usize,
    overflow_count: u64,
}

impl<const N: usize> LogRingBuffer<N> {
    /// Create a new empty ring buffer
    pub const fn new() -> Self {
        Self {
            entries: [CompactLogEntry::new(); N],
            head: 0,
            tail: 0,
            count: 0,
            overflow_count: 0,
        }
    }

    /// Push a log entry (overwrites oldest if full)
    pub fn push(&mut self, entry: &LogEntry) {
        let compact = CompactLogEntry::from_entry(entry);
        self.push_compact(compact);
    }

    /// Push a compact log entry
    pub fn push_compact(&mut self, entry: CompactLogEntry) {
        self.entries[self.head] = entry;
        self.head = (self.head + 1) % N;
        if self.count < N {
            self.count += 1;
        } else {
            // Overflow oldest entry is lost
            self.tail = (self.tail + 1) % N;
            self.overflow_count += 1;
        }
    }

    /// Push a simple log message
    pub fn push_message(&mut self, tick: u64, level: LogLevel, category_hash: u8, message: &str) {
        let mut entry = CompactLogEntry::new();
        entry.tick = tick;
        entry.level = level as u8;
        entry.category_hash = category_hash;

        let msg_bytes = message.as_bytes();
        let msg_len = msg_bytes.len().min(52);
        entry.message[..msg_len].copy_from_slice(&msg_bytes[..msg_len]);
        entry.message_len = msg_len as u16;

        self.push_compact(entry);
    }

    /// Get number of entries currently stored
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if buffer is full
    pub fn is_full(&self) -> bool {
        self.count >= N
    }

    /// Get buffer capacity
    pub fn capacity(&self) -> usize {
        N
    }

    pub fn overflow_count(&self) -> u64 {
        self.overflow_count
    }

    /// Get entry at index (0 = oldest)
    pub fn get(&self, index: usize) -> Option<&CompactLogEntry> {
        if index >= self.count {
            return None;
        }
        let actual_idx = (self.tail + index) % N;
        Some(&self.entries[actual_idx])
    }

    pub fn last(&self) -> Option<&CompactLogEntry> {
        if self.count == 0 {
            return None;
        }
        let idx = if self.head == 0 { N - 1 } else { self.head - 1 };
        Some(&self.entries[idx])
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
        // ## Note: we don't reset overflow_count to preserve history
    }

    /// Iterate over entries from oldest to newest
    pub fn iter(&self) -> LogRingIterator<'_, N> {
        LogRingIterator {
            buffer: self,
            current: 0,
        }
    }

    /// Get entries filtered by minimum level
    pub fn filter_by_level(&self, min_level: LogLevel) -> impl Iterator<Item = &CompactLogEntry> {
        self.iter()
            .filter(move |e| e.log_level().should_log(min_level))
    }
}

impl<const N: usize> Default for LogRingBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator over ring buffer entries
pub struct LogRingIterator<'a, const N: usize> {
    buffer: &'a LogRingBuffer<N>,
    current: usize,
}

impl<'a, const N: usize> Iterator for LogRingIterator<'a, N> {
    type Item = &'a CompactLogEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.buffer.count {
            return None;
        }
        let entry = self.buffer.get(self.current);
        self.current += 1;
        entry
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.buffer.count - self.current;
        (remaining, Some(remaining))
    }
}

impl<'a, const N: usize> ExactSizeIterator for LogRingIterator<'a, N> {}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Push one more should overflow
        buf.push_message(5, LogLevel::Info, 0, "test5");
        assert_eq!(buf.len(), 4);
        assert_eq!(buf.overflow_count(), 1);
        // First entry should now be test2
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
}
