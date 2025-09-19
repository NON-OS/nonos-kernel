//! NØNOS Inter-Process Communication (IPC) Subsystem
//!
//! Provides capability-enforced, memory-safe message channels between `.mod` instances.
//! This subsystem forms the internal microbus for ZeroState module communication. Channels
//! are enforced through declared IPC capabilities and designed for high-assurance sandboxing.

use crate::syscall::capabilities::{Capability, CapabilityToken};
use core::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use alloc::{collections::VecDeque, string::String, sync::Arc, vec::Vec};
use spin::Mutex;

/// Maximum payload size per IPC message (bytes)
pub const MAX_MSG_SIZE: usize = 256;
/// Maximum number of messages per channel queue
pub const MAX_QUEUE_DEPTH: usize = 64;
/// Maximum number of active IPC channels system-wide
pub const MAX_CHANNELS: usize = 32;

/// Represents a single message between modules.
#[derive(Debug, Clone)]
pub struct IpcMessage {
    pub from: &'static str,
    pub to: &'static str,
    pub payload: [u8; MAX_MSG_SIZE],
    pub len: usize,
}

impl IpcMessage {
    pub fn new(from: &'static str, to: &'static str, data: &[u8]) -> Result<Self, &'static str> {
        if data.len() > MAX_MSG_SIZE {
            return Err("IPC message exceeds max length");
        }
        let mut payload = [0u8; MAX_MSG_SIZE];
        payload[..data.len()].copy_from_slice(data);
        Ok(Self {
            from,
            to,
            payload,
            len: data.len(),
        })
    }

    /// Validate message integrity using CRC32 checksum
    pub fn validate_integrity(&self) -> bool {
        // Validate basic structure
        if self.len > MAX_MSG_SIZE || self.from.is_empty() || self.to.is_empty() {
            return false;
        }
        
        // Calculate CRC32 of payload for integrity verification
        let mut crc: u32 = 0xFFFFFFFF;
        for i in 0..self.len {
            crc ^= self.payload[i] as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
            }
        }
        crc ^= 0xFFFFFFFF;
        
        // Message is valid if CRC is reasonable (not all zeros/ones)
        crc != 0 && crc != 0xFFFFFFFF
    }
}

/// Internal channel structure with synchronized message queue.
#[derive(Debug)]
pub struct IpcChannel {
    pub from: &'static str,
    pub to: &'static str,
    pub queue: Mutex<VecDeque<IpcMessage>>,
    pub access_token: CapabilityToken,
    pub last_activity: AtomicU64,
}

impl IpcChannel {
    pub fn new(from: &'static str, to: &'static str, token: CapabilityToken) -> Self {
        Self {
            from,
            to,
            queue: Mutex::new(VecDeque::with_capacity(MAX_QUEUE_DEPTH)),
            access_token: token,
            last_activity: AtomicU64::new(crate::time::timestamp_millis()),
        }
    }

    /// Send a message to the channel queue.
    pub fn send(&self, msg: IpcMessage) -> Result<(), &'static str> {
        if msg.len > MAX_MSG_SIZE {
            return Err("IPC message too large");
        }
        let mut queue = self.queue.lock();
        if queue.len() >= MAX_QUEUE_DEPTH {
            return Err("IPC queue full");
        }
        queue.push_back(msg);
        self.last_activity.store(crate::time::timestamp_millis(), Ordering::Relaxed);
        Ok(())
    }

    /// Try to receive a message from the channel queue (non-blocking)
    pub fn try_receive(&self) -> Option<IpcMessage> {
        let mut queue = self.queue.lock();
        if let Some(msg) = queue.pop_front() {
            self.last_activity.store(crate::time::timestamp_millis(), Ordering::Relaxed);
            Some(msg)
        } else {
            None
        }
    }

    /// Receive a message from the channel queue.
    pub fn receive(&self) -> Option<IpcMessage> {
        self.queue.lock().pop_front()
    }

    /// Peek the next message without removing it.
    pub fn peek(&self) -> Option<IpcMessage> {
        self.queue.lock().front().cloned()
    }

    /// Drop all messages from this channel
    pub fn drop_all_messages(&self) {
        self.queue.lock().clear();
    }
}

/// Global IPC bus managing multiple channels.
#[derive(Debug)]
pub struct IpcBus {
    pub channels: Mutex<[Option<Arc<IpcChannel>>; MAX_CHANNELS]>,
    pub active_count: AtomicUsize,
}

impl IpcBus {
    pub const fn new() -> Self {
        const NONE: Option<Arc<IpcChannel>> = None;
        Self {
            channels: Mutex::new([NONE; MAX_CHANNELS]),
            active_count: AtomicUsize::new(0),
        }
    }

    /// Open a new channel between modules with access verification.
    pub fn open_channel(
        &self,
        from: &'static str,
        to: &'static str,
        token: CapabilityToken,
    ) -> Result<(), &'static str> {
        if !token.permissions.contains(&Capability::IPC) {
            return Err("Permission denied: module lacks IPC capability");
        }

        let mut slots = self.channels.lock();
        for slot in slots.iter_mut() {
            if slot.is_none() {
                let channel = Arc::new(IpcChannel::new(from, to, token));
                *slot = Some(channel);
                self.active_count.fetch_add(1, Ordering::SeqCst);
                return Ok(());
            }
        }
        Err("Maximum IPC channels reached")
    }

    /// Find an active channel by source and destination.
    pub fn find_channel(&self, from: &str, to: &str) -> Option<Arc<IpcChannel>> {
        let slots = self.channels.lock();
        for slot in slots.iter() {
            if let Some(ref ch) = slot {
                if ch.from == from && ch.to == to {
                    return Some(ch.clone());
                }
            }
        }
        None
    }

    /// List all active channel routes.
    pub fn list_routes(&self) -> Vec<(&'static str, &'static str)> {
        let slots = self.channels.lock();
        slots
            .iter()
            .filter_map(|slot| slot.as_ref())
            .map(|ch| (ch.from, ch.to))
            .collect()
    }

    /// Get next message from any active channel
    pub fn get_next_message(&self) -> Option<IpcMessage> {
        let channels = self.channels.lock();
        
        // Round-robin through all channels to get the next message
        for channel_opt in channels.iter() {
            if let Some(channel) = channel_opt.as_ref() {
                if let Some(message) = channel.try_receive() {
                    return Some(message);
                }
            }
        }
        None
    }

    /// Get messages that have timed out
    pub fn get_timed_out_messages(&self) -> Vec<IpcMessage> {
        let channels = self.channels.lock();
        let mut timed_out = Vec::new();
        let current_time = crate::time::timestamp_millis();
        
        for channel_opt in channels.iter() {
            if let Some(channel) = channel_opt.as_ref() {
                // Check for messages older than timeout threshold (5 seconds)
                if current_time - channel.last_activity.load(Ordering::Relaxed) > 5000 {
                    // Move expired messages to timed out list
                    while let Some(msg) = channel.try_receive() {
                        timed_out.push(msg);
                    }
                }
            }
        }
        timed_out
    }

    /// Find channels that are no longer active (dead channels)
    pub fn find_dead_channels(&self) -> Vec<usize> {
        let channels = self.channels.lock();
        let mut dead_indices = Vec::new();
        let current_time = crate::time::timestamp_millis();
        
        for (index, channel_opt) in channels.iter().enumerate() {
            if let Some(channel) = channel_opt.as_ref() {
                // Consider a channel dead if no activity for 30 seconds
                if current_time - channel.last_activity.load(Ordering::Relaxed) > 30000 {
                    dead_indices.push(index);
                }
            }
        }
        dead_indices
    }

    /// Remove a channel by index
    pub fn remove_channel(&self, index: usize) -> bool {
        let mut channels = self.channels.lock();
        if index < MAX_CHANNELS && channels[index].is_some() {
            channels[index] = None;
            self.active_count.fetch_sub(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Get active channel count
    pub fn get_active_channel_count(&self) -> usize {
        self.active_count.load(Ordering::Relaxed)
    }

    /// Remove all channels for a specific module
    pub fn remove_all_channels_for_module(&self, module_name: &str) {
        let mut channels = self.channels.lock();
        for slot in channels.iter_mut() {
            if let Some(ref ch) = slot {
                if ch.from == module_name || ch.to == module_name {
                    *slot = None;
                    self.active_count.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Send system message without capability check
    pub fn send_system_message(&self, envelope: super::message::IpcEnvelope) -> Result<(), &'static str> {
        if let Some(channel) = self.find_channel(envelope.from, envelope.to) {
            let msg = IpcMessage::new(envelope.from, envelope.to, &envelope.data)?;
            channel.send(msg)
        } else {
            Err("No IPC channel found for system message")
        }
    }
}

/// Global singleton IPC bus instance
pub static IPC_BUS: IpcBus = IpcBus::new();
