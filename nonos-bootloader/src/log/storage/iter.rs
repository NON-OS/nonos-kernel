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
use crate::log::types::CompactLogEntry;

/// Iterator over ring buffer entries
pub struct LogRingIterator<'a, const N: usize> {
    pub(super) buffer: &'a LogRingBuffer<N>,
    pub(super) current: usize,
}

impl<'a, const N: usize> Iterator for LogRingIterator<'a, N> {
    type Item = &'a CompactLogEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.buffer.len() {
            return None;
        }
        let entry = self.buffer.get(self.current);
        self.current += 1;
        entry
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.buffer.len() - self.current;
        (remaining, Some(remaining))
    }
}

impl<'a, const N: usize> ExactSizeIterator for LogRingIterator<'a, N> {}
