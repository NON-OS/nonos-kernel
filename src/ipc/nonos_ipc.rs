#![no_std]

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, RwLock};

/// Channel types for the PID-based IPC manager (independent of the bus routes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonosChannelType {
    SharedMemory = 0x1000,
    MessagePassing = 0x2000,
    Signal = 0x3000,
    Pipe = 0x4000,
    Socket = 0x5000,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonosMessageType {
    Data = 0x1000,
    Control = 0x2000,
    Synchronization = 0x3000,
    Signal = 0x4000,
    Error = 0x5000,
}

#[derive(Debug, Clone)]
pub struct NonosIPCMessage {
    pub message_id: u64,
    pub sender_id: u64,
    pub recipient_id: u64,
    pub message_type: NonosMessageType,
    pub payload: Vec<u8>,
    pub timestamp_ms: u64,
    pub priority: u8,
}

struct ChannelQueue {
    queue: alloc::collections::VecDeque<NonosIPCMessage>,
    cap: usize,
}

impl ChannelQueue {
    fn new(cap: usize) -> Self {
        Self {
            queue: alloc::collections::VecDeque::with_capacity(cap),
            cap,
        }
    }
    #[inline]
    fn is_full(&self) -> bool {
        self.queue.len() >= self.cap
    }
    fn push(&mut self, msg: NonosIPCMessage) -> Result<(), &'static str> {
        if self.is_full() {
            Err("channel queue full")
        } else {
            self.queue.push_back(msg);
            Ok(())
        }
    }
    fn pop_for(&mut self, receiver_id: u64) -> Option<NonosIPCMessage> {
        if let Some(pos) = self.queue.iter().position(|m| m.recipient_id == receiver_id) {
            return self.queue.remove(pos);
        }
        None
    }
}

/// Channel metadata and queue
#[derive(Debug)]
pub struct NonosIPCChannel {
    pub channel_id: u64,
    pub channel_type: NonosChannelType,
    pub participants: Vec<u64>,                    // allowed PIDs
    pub encryption_enabled: bool,
    queue: Mutex<ChannelQueue>,                    // bounded per-channel queue
}

impl NonosIPCChannel {
    fn new(channel_id: u64, channel_type: NonosChannelType, participants: Vec<u64>, cap: usize) -> Self {
        Self {
            channel_id,
            channel_type,
            participants,
            encryption_enabled: false,
            queue: Mutex::new(ChannelQueue::new(cap)),
        }
    }

    #[inline]
    fn has_participant(&self, pid: u64) -> bool {
        self.participants.iter().any(|&p| p == pid)
    }
}

/// PID-oriented IPC manager 
pub struct NonosIPCManager {
    channels: RwLock<BTreeMap<u64, NonosIPCChannel>>,
    process_channels: RwLock<BTreeMap<u64, Vec<u64>>>, // pid -> channel_ids
    next_channel_id: AtomicU64,
    next_message_id: AtomicU64,
    default_queue_cap: AtomicU64,
}

impl NonosIPCManager {
    pub const fn new() -> Self {
        Self {
            channels: RwLock::new(BTreeMap::new()),
            process_channels: RwLock::new(BTreeMap::new()),
            next_channel_id: AtomicU64::new(1),
            next_message_id: AtomicU64::new(1),
            default_queue_cap: AtomicU64::new(1024),
        }
    }

    /// adjust default per-channel queue capacity 
    pub fn set_default_queue_capacity(&self, cap: usize) {
        self.default_queue_cap.store(cap as u64, Ordering::Relaxed);
    }

    /// Create a channel among participants; creator must be included in participants
    pub fn create_channel(
        &self,
        creator_id: u64,
        channel_type: NonosChannelType,
        mut participants: Vec<u64>,
    ) -> Result<u64, &'static str> {
        if !participants.iter().any(|&p| p == creator_id) {
            participants.push(creator_id);
        }
        if participants.is_empty() {
            return Err("participants empty");
        }
        let channel_id = self.next_channel_id.fetch_add(1, Ordering::Relaxed);
        let cap = self.default_queue_cap.load(Ordering::Relaxed) as usize;

        let channel = NonosIPCChannel::new(channel_id, channel_type, participants.clone(), cap);
        {
            let mut ch_map = self.channels.write();
            if ch_map.contains_key(&channel_id) {
                return Err("channel id collision");
            }
            ch_map.insert(channel_id, channel);
        }
        {
            let mut proc_map = self.process_channels.write();
            for pid in participants {
                proc_map.entry(pid).or_insert_with(Vec::new).push(channel_id);
            }
        }
        Ok(channel_id)
    }

    /// Send a message to recipient on a channel. Sender and recipient must be participants.
    pub fn send_message(
        &self,
        sender_id: u64,
        channel_id: u64,
        recipient_id: u64,
        message_type: NonosMessageType,
        payload: Vec<u8>,
    ) -> Result<u64, &'static str> {
        let now = crate::time::timestamp_millis();
        let msg_id = self.next_message_id.fetch_add(1, Ordering::Relaxed);

        // Acquire channel
        let ch_opt = { self.channels.read().get(&channel_id).cloned() };
        let mut guard;
        let ch_ref = if let Some(ch) = ch_opt {
            // We cloned metadata; re-acquire to mutate queue
            guard = self.channels.write();
            guard.get_mut(&channel_id).unwrap()
        } else {
            return Err("channel not found");
        };

        // Permissions
        if !ch_ref.has_participant(sender_id) {
            return Err("sender not authorized for channel");
        }
        if !ch_ref.has_participant(recipient_id) {
            return Err("recipient not authorized for channel");
        }

        let priority = Self::calculate_message_priority(message_type);
        let msg = NonosIPCMessage {
            message_id: msg_id,
            sender_id,
            recipient_id,
            message_type,
            payload,
            timestamp_ms: now,
            priority,
        };

        // Enqueue (bounded)
        let mut q = ch_ref.queue.lock();
        q.push(msg)?;

        Ok(msg_id)
    }

    /// Receive next message for receiver on a channel
    pub fn receive_message(
        &self,
        receiver_id: u64,
        channel_id: u64,
    ) -> Result<Option<NonosIPCMessage>, &'static str> {
        let mut ch_map = self.channels.write();
        let ch = ch_map.get_mut(&channel_id).ok_or("channel not found")?;
        if !ch.has_participant(receiver_id) {
            return Err("receiver not authorized for channel");
        }
        Ok(ch.queue.lock().pop_for(receiver_id))
    }

    /// Destroy a channel; only participants are allowed to request destruction
    pub fn destroy_channel(&self, destroyer_id: u64, channel_id: u64) -> Result<(), &'static str> {
        let mut ch_map = self.channels.write();
        let ch = ch_map.get(&channel_id).ok_or("channel not found")?;
        if !ch.has_participant(destroyer_id) {
            return Err("destroyer not authorized for channel");
        }
        let participants = ch.participants.clone();
        ch_map.remove(&channel_id);

        // Remove cross-references
        let mut proc_map = self.process_channels.write();
        for pid in participants {
            if let Some(list) = proc_map.get_mut(&pid) {
                list.retain(|&cid| cid != channel_id);
                if list.is_empty() {
                    proc_map.remove(&pid);
                }
            }
        }
        Ok(())
    }

    #[inline]
    fn calculate_message_priority(message_type: NonosMessageType) -> u8 {
        match message_type {
            NonosMessageType::Control => 255,
            NonosMessageType::Signal => 200,
            NonosMessageType::Error => 180,
            NonosMessageType::Synchronization => 150,
            NonosMessageType::Data => 100,
        }
    }

    #[inline]
    pub fn get_channel_count(&self) -> usize {
        self.channels.read().len()
    }

    pub fn get_process_channels(&self, process_id: u64) -> Vec<u64> {
        self.process_channels
            .read()
            .get(&process_id)
            .cloned()
            .unwrap_or_else(Vec::new)
    }
}

// Global IPC manager instance (PID-oriented)
pub static NONOS_IPC_MANAGER: NonosIPCManager = NonosIPCManager::new();

// Convenience wrappers
pub fn create_ipc_channel(
    creator_id: u64,
    channel_type: NonosChannelType,
    participants: Vec<u64>,
) -> Result<u64, &'static str> {
    NONOS_IPC_MANAGER.create_channel(creator_id, channel_type, participants)
}

pub fn send_ipc_message(
    sender_id: u64,
    channel_id: u64,
    recipient_id: u64,
    message_type: NonosMessageType,
    payload: Vec<u8>,
) -> Result<u64, &'static str> {
    NONOS_IPC_MANAGER.send_message(sender_id, channel_id, recipient_id, message_type, payload)
}

pub fn receive_ipc_message(
    receiver_id: u64,
    channel_id: u64,
) -> Result<Option<NonosIPCMessage>, &'static str> {
    NONOS_IPC_MANAGER.receive_message(receiver_id, channel_id)
}

pub fn destroy_ipc_channel(destroyer_id: u64, channel_id: u64) -> Result<(), &'static str> {
    NONOS_IPC_MANAGER.destroy_channel(destroyer_id, channel_id)
}
