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

extern crate alloc;

use alloc::{string::String, vec, vec::Vec};
use spin::{Mutex, Once};

use super::types::{FileInfo, MAX_OPERATION_RETRIES, WRITEBACK_BATCH_SIZE};

static WRITEBACK_QUEUE: Once<Mutex<WritebackQueue>> = Once::new();

struct WritebackQueue {
    files: Vec<FileInfo>,
    retry_list: Vec<FileInfo>,
}

impl WritebackQueue {
    fn new() -> Self {
        Self {
            files: Vec::new(),
            retry_list: Vec::new(),
        }
    }

    fn add_file(&mut self, path: String, inode: u64) {
        if !self.files.iter().any(|f| f.inode == inode) {
            self.files.push(FileInfo {
                path,
                inode,
                retries: 0,
                last_attempt: 0,
            });
        }
    }

    fn get_pending(&self, max: usize) -> Vec<FileInfo> {
        self.files.iter().take(max).cloned().collect()
    }

    fn mark_complete(&mut self, inode: u64) {
        self.files.retain(|f| f.inode != inode);
    }

    fn schedule_retry(&mut self, file: &FileInfo) {
        if file.retries < MAX_OPERATION_RETRIES {
            let mut retry = file.clone();
            retry.retries += 1;
            retry.last_attempt = crate::time::current_ticks();
            self.retry_list.push(retry);
        }
    }

    fn clear(&mut self) {
        self.files.clear();
        self.retry_list.clear();
    }
}

pub fn init_writeback_queue() {
    WRITEBACK_QUEUE.call_once(|| Mutex::new(WritebackQueue::new()));
}

pub fn get_writeback_files() -> Vec<FileInfo> {
    init_writeback_queue();
    if let Some(queue) = WRITEBACK_QUEUE.get() {
        return queue.lock().get_pending(WRITEBACK_BATCH_SIZE);
    }
    vec![]
}

pub fn mark_file_clean(file: &FileInfo) {
    init_writeback_queue();
    if let Some(queue) = WRITEBACK_QUEUE.get() {
        queue.lock().mark_complete(file.inode);
    }
}

pub fn schedule_writeback_retry(file: &FileInfo) {
    init_writeback_queue();
    if let Some(queue) = WRITEBACK_QUEUE.get() {
        queue.lock().schedule_retry(file);
    }
}

pub fn clear_writeback_queue() {
    init_writeback_queue();
    if let Some(queue) = WRITEBACK_QUEUE.get() {
        queue.lock().clear();
    }
}
