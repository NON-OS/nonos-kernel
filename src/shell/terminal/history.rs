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

use core::ptr::addr_of_mut;

pub const HISTORY_SIZE: usize = 64;
pub const MAX_CMD_LEN: usize = 256;

pub struct CommandHistory {
    entries: [[u8; MAX_CMD_LEN]; HISTORY_SIZE],
    lengths: [usize; HISTORY_SIZE],
    count: usize,
    head: usize,
    browse_pos: usize,
    saved_line: [u8; MAX_CMD_LEN],
    saved_len: usize,
    browsing: bool,
}

impl CommandHistory {
    pub const fn new() -> Self {
        Self {
            entries: [[0u8; MAX_CMD_LEN]; HISTORY_SIZE],
            lengths: [0; HISTORY_SIZE],
            count: 0,
            head: 0,
            browse_pos: 0,
            saved_line: [0u8; MAX_CMD_LEN],
            saved_len: 0,
            browsing: false,
        }
    }

    pub fn add(&mut self, cmd: &[u8]) {
        if cmd.is_empty() {
            return;
        }

        if self.count > 0 {
            let last_idx = if self.head == 0 {
                HISTORY_SIZE - 1
            } else {
                self.head - 1
            };
            if self.lengths[last_idx] == cmd.len()
                && &self.entries[last_idx][..cmd.len()] == cmd
            {
                return;
            }
        }

        let len = cmd.len().min(MAX_CMD_LEN);
        self.entries[self.head][..len].copy_from_slice(&cmd[..len]);
        self.lengths[self.head] = len;

        self.head = (self.head + 1) % HISTORY_SIZE;
        if self.count < HISTORY_SIZE {
            self.count += 1;
        }

        self.browsing = false;
    }

    pub fn start_browse(&mut self, current_line: &[u8]) {
        if !self.browsing {
            let len = current_line.len().min(MAX_CMD_LEN);
            self.saved_line[..len].copy_from_slice(&current_line[..len]);
            self.saved_len = len;
            self.browse_pos = self.count;
            self.browsing = true;
        }
    }

    pub fn prev(&mut self) -> Option<(&[u8], usize)> {
        if self.count == 0 {
            return None;
        }

        if self.browse_pos > 0 {
            self.browse_pos -= 1;
            let idx = self.index_for_browse_pos(self.browse_pos);
            let len = self.lengths[idx];
            return Some((&self.entries[idx][..len], len));
        }

        None
    }

    pub fn next(&mut self) -> Option<(&[u8], usize)> {
        if !self.browsing {
            return None;
        }

        if self.browse_pos < self.count {
            self.browse_pos += 1;

            if self.browse_pos == self.count {
                self.browsing = false;
                return Some((&self.saved_line[..self.saved_len], self.saved_len));
            }

            let idx = self.index_for_browse_pos(self.browse_pos);
            let len = self.lengths[idx];
            return Some((&self.entries[idx][..len], len));
        }

        None
    }

    pub fn cancel_browse(&mut self) {
        self.browsing = false;
    }

    pub fn is_browsing(&self) -> bool {
        self.browsing
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn get(&self, index: usize) -> Option<(&[u8], usize)> {
        if index >= self.count {
            return None;
        }

        let idx = self.index_for_browse_pos(index);
        let len = self.lengths[idx];
        Some((&self.entries[idx][..len], len))
    }

    fn index_for_browse_pos(&self, pos: usize) -> usize {
        let oldest = if self.count < HISTORY_SIZE {
            0
        } else {
            self.head
        };
        (oldest + pos) % HISTORY_SIZE
    }

    pub fn clear(&mut self) {
        for i in 0..HISTORY_SIZE {
            for j in 0..MAX_CMD_LEN {
                self.entries[i][j] = 0;
            }
            self.lengths[i] = 0;
        }
        self.count = 0;
        self.head = 0;
        self.browse_pos = 0;
        self.browsing = false;
        self.saved_len = 0;
    }

    pub fn secure_erase(&mut self) {
        for i in 0..HISTORY_SIZE {
            for j in 0..MAX_CMD_LEN {
                // SAFETY: write_volatile ensures the compiler doesn't optimize away
                // the zeroing operation, which is important for secure erasure.
                unsafe {
                    core::ptr::write_volatile(&mut self.entries[i][j], 0);
                }
            }
            self.lengths[i] = 0;
        }
        self.count = 0;
        self.head = 0;
        self.browse_pos = 0;
        self.browsing = false;
        self.saved_len = 0;

        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

static mut HISTORY: CommandHistory = CommandHistory::new();

pub fn get_history() -> &'static mut CommandHistory {
    // SAFETY: Command history is only accessed from the main thread during terminal
    // operations. No concurrent access occurs as the shell is single-threaded.
    // Using addr_of_mut! to avoid creating a mutable reference to the static directly.
    unsafe { &mut *addr_of_mut!(HISTORY) }
}

pub fn init() {
    get_history().clear();
}

pub fn add_command(cmd: &[u8]) {
    get_history().add(cmd);
}

pub fn prev_command(current: &[u8]) -> Option<(&'static [u8], usize)> {
    let h = get_history();
    h.start_browse(current);
    h.prev()
}

pub fn next_command() -> Option<(&'static [u8], usize)> {
    get_history().next()
}

pub fn secure_erase() {
    get_history().secure_erase();
}
