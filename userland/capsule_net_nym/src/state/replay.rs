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

use crate::packet::REPLAY_TAG_LEN;

const DEPTH: usize = 64;

pub struct ReplayWindow {
    tags: [[u8; REPLAY_TAG_LEN]; DEPTH],
    used: [bool; DEPTH],
    next: usize,
}

impl ReplayWindow {
    pub const fn new() -> Self {
        Self { tags: [[0u8; REPLAY_TAG_LEN]; DEPTH], used: [false; DEPTH], next: 0 }
    }

    pub fn accept(&mut self, tag: &[u8; REPLAY_TAG_LEN]) -> bool {
        if self.seen(tag) {
            return false;
        }
        self.tags[self.next] = *tag;
        self.used[self.next] = true;
        self.next = (self.next + 1) % DEPTH;
        true
    }

    fn seen(&self, tag: &[u8; REPLAY_TAG_LEN]) -> bool {
        self.used.iter().zip(self.tags.iter()).any(|(used, old)| *used && old == tag)
    }
}
