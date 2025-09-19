#![no_std]

use alloc::{vec::Vec, collections::BTreeMap};
use spin::{RwLock, Mutex};
use x86_64::{PhysAddr, VirtAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonosChannelType {
    SharedMemory = 0x1000,
    MessagePassing = 0x2000,
    Signal = 0x3000,
    Pipe = 0x4000,
    Socket = 0x5000,
    QuantumChannel = 0x6000,
}

#[derive(Debug, Clone, Copy)]
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
    pub timestamp: u64,
    pub priority: u8,
}

#[derive(Debug)]
pub struct NonosIPCChannel {
    pub channel_id: u64,
    pub channel_type: NonosChannelType,
    pub participants: Vec<u64>,
    pub message_queue: Mutex<Vec<NonosIPCMessage>>,
    pub encryption_enabled: bool,
}

#[derive(Debug)]
pub struct NonosIPCManager {
    channels: RwLock<BTreeMap<u64, NonosIPCChannel>>,
    process_channels: RwLock<BTreeMap<u64, Vec<u64>>>,
    next_channel_id: Mutex<u64>,
}

impl NonosIPCManager {
    pub const fn new() -> Self {
        Self {
            channels: RwLock::new(BTreeMap::new()),
            process_channels: RwLock::new(BTreeMap::new()),
            next_channel_id: Mutex::new(1),
        }
    }

    pub fn create_channel(
        &self,
        _creator_id: u64,
        channel_type: NonosChannelType,
        participants: Vec<u64>
    ) -> Result<u64, &'static str> {
        let channel_id = {
            let mut next_id = self.next_channel_id.lock();
            let id = *next_id;
            *next_id += 1;
            id
        };

        let channel = NonosIPCChannel {
            channel_id,
            channel_type,
            participants: participants.clone(),
            message_queue: Mutex::new(Vec::new()),
            encryption_enabled: true,
        };

        // Register channel
        self.channels.write().insert(channel_id, channel);
        
        // Update process-channel mapping
        let mut process_channels = self.process_channels.write();
        for participant in participants {
            process_channels.entry(participant).or_insert_with(Vec::new).push(channel_id);
        }
        
        Ok(channel_id)
    }

    pub fn send_message(
        &self,
        sender_id: u64,
        channel_id: u64,
        recipient_id: u64,
        message_type: NonosMessageType,
        payload: Vec<u8>
    ) -> Result<u64, &'static str> {
        let channels = self.channels.read();
        let channel = channels.get(&channel_id).ok_or("Channel not found")?;
        
        // Permission check
        if !channel.participants.contains(&sender_id) {
            return Err("Sender not authorized for channel");
        }

        let message_id = self.get_timestamp();
        let message = NonosIPCMessage {
            message_id,
            sender_id,
            recipient_id,
            message_type,
            payload,
            timestamp: message_id,
            priority: self.calculate_message_priority(message_type),
        };

        // Add to message queue
        channel.message_queue.lock().push(message);
        
        Ok(message_id)
    }

    pub fn receive_message(
        &self,
        receiver_id: u64,
        channel_id: u64
    ) -> Result<Option<NonosIPCMessage>, &'static str> {
        let channels = self.channels.read();
        let channel = channels.get(&channel_id).ok_or("Channel not found")?;
        
        // Permission check
        if !channel.participants.contains(&receiver_id) {
            return Err("Receiver not authorized for channel");
        }

        let mut queue = channel.message_queue.lock();
        
        // Find message for this receiver
        let mut found_index = None;
        for (i, message) in queue.iter().enumerate() {
            if message.recipient_id == receiver_id {
                found_index = Some(i);
                break;
            }
        }

        if let Some(index) = found_index {
            Ok(Some(queue.remove(index)))
        } else {
            Ok(None)
        }
    }

    pub fn destroy_channel(&self, destroyer_id: u64, channel_id: u64) -> Result<(), &'static str> {
        let mut channels = self.channels.write();
        let channel = channels.get(&channel_id).ok_or("Channel not found")?;
        
        // Permission check - only participants can destroy channel
        if !channel.participants.contains(&destroyer_id) {
            return Err("Destroyer not authorized for channel");
        }

        // Update process-channel mapping
        let mut process_channels = self.process_channels.write();
        for participant in &channel.participants {
            if let Some(channel_list) = process_channels.get_mut(participant) {
                channel_list.retain(|&id| id != channel_id);
            }
        }

        // Remove channel
        channels.remove(&channel_id);
        
        Ok(())
    }

    fn calculate_message_priority(&self, message_type: NonosMessageType) -> u8 {
        match message_type {
            NonosMessageType::Control => 255,
            NonosMessageType::Signal => 200,
            NonosMessageType::Error => 180,
            NonosMessageType::Synchronization => 150,
            NonosMessageType::Data => 100,
        }
    }

    fn get_timestamp(&self) -> u64 {
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    pub fn get_channel_count(&self) -> usize {
        self.channels.read().len()
    }

    pub fn get_process_channels(&self, process_id: u64) -> Vec<u64> {
        self.process_channels.read()
            .get(&process_id)
            .cloned()
            .unwrap_or_else(Vec::new)
    }
}

// Global IPC manager instance
pub static NONOS_IPC_MANAGER: NonosIPCManager = NonosIPCManager::new();

// Convenience functions
pub fn create_ipc_channel(
    creator_id: u64,
    channel_type: NonosChannelType,
    participants: Vec<u64>
) -> Result<u64, &'static str> {
    NONOS_IPC_MANAGER.create_channel(creator_id, channel_type, participants)
}

pub fn send_ipc_message(
    sender_id: u64,
    channel_id: u64,
    recipient_id: u64,
    message_type: NonosMessageType,
    payload: Vec<u8>
) -> Result<u64, &'static str> {
    NONOS_IPC_MANAGER.send_message(sender_id, channel_id, recipient_id, message_type, payload)
}

pub fn receive_ipc_message(
    receiver_id: u64,
    channel_id: u64
) -> Result<Option<NonosIPCMessage>, &'static str> {
    NONOS_IPC_MANAGER.receive_message(receiver_id, channel_id)
}

pub fn destroy_ipc_channel(destroyer_id: u64, channel_id: u64) -> Result<(), &'static str> {
    NONOS_IPC_MANAGER.destroy_channel(destroyer_id, channel_id)
}