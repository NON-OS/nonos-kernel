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
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use spin::Mutex;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use super::mount::Ext4MountInfo;

pub const JBD2_MAGIC: u32 = 0xC03B3998;
pub const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
pub const JBD2_COMMIT_BLOCK: u32 = 2;
pub const JBD2_SUPERBLOCK_V2: u32 = 4;

pub struct Ext4Journal {
    pub mount: Arc<Ext4MountInfo>,
    pub journal_ino: u32,
    pub sequence: AtomicU32,
    pub running_transaction: Mutex<Option<JournalTransaction>>,
    pub committing: AtomicBool,
    pub checkpoint_list: Mutex<VecDeque<u32>>,
}

pub struct JournalTransaction {
    pub tid: u32,
    pub state: TransactionState,
    pub buffers: Vec<JournalBuffer>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransactionState { Running, Locked, Flush, Commit, Finished }

pub struct JournalBuffer {
    pub block: u64,
    pub data: Vec<u8>,
    pub metadata: bool,
}

impl Ext4Journal {
    pub fn new(mount: Arc<Ext4MountInfo>, journal_ino: u32) -> Self {
        Self {
            mount, journal_ino, sequence: AtomicU32::new(1),
            running_transaction: Mutex::new(None), committing: AtomicBool::new(false),
            checkpoint_list: Mutex::new(VecDeque::new()),
        }
    }

    pub fn get_write_access(&self, block: u64, data: Vec<u8>, metadata: bool) -> Result<(), i32> {
        let mut txn = self.running_transaction.lock();
        if let Some(ref mut t) = *txn {
            t.buffers.push(JournalBuffer { block, data, metadata });
        }
        Ok(())
    }
}

pub fn journal_start(journal: &Arc<Ext4Journal>, nblocks: u32) -> Result<u32, i32> {
    let mut txn = journal.running_transaction.lock();
    if let Some(ref existing) = *txn { return Ok(existing.tid); }
    let tid = journal.sequence.fetch_add(1, Ordering::SeqCst);
    let buffers = Vec::with_capacity(nblocks as usize);
    *txn = Some(JournalTransaction { tid, state: TransactionState::Running, buffers });
    Ok(tid)
}

pub fn journal_stop(journal: &Arc<Ext4Journal>, tid: u32) -> Result<(), i32> {
    let txn = journal.running_transaction.lock();
    if let Some(ref t) = *txn {
        if t.tid != tid { return Err(-22); }
    }
    Ok(())
}

pub fn journal_commit(journal: &Arc<Ext4Journal>) -> Result<(), i32> {
    if journal.committing.swap(true, Ordering::SeqCst) { return Err(-16); }
    let mut txn_guard = journal.running_transaction.lock();
    if let Some(mut txn) = txn_guard.take() {
        txn.state = TransactionState::Commit;
        for buf in &txn.buffers {
            crate::drivers::block::write(&journal.mount.device, &buf.data, buf.block * journal.mount.sb.block_size() as u64)?;
        }
        journal.checkpoint_list.lock().push_back(txn.tid);
    }
    journal.committing.store(false, Ordering::SeqCst);
    Ok(())
}
