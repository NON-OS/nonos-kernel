#![no_std]

extern crate alloc;

use alloc::{collections::VecDeque, string::String, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::{Mutex, RwLock};

/// Message item moved across IPC bus
#[derive(Debug, Clone)]
pub struct IpcMessage {
    pub from: String,
    pub to: String,
    pub data: Vec<u8>,
    pub timestamp_ms: u64,
    checksum64: u64,
}

impl IpcMessage {
    pub fn new(from: &str, to: &str, data: &[u8]) -> Result<Self, &'static str> {
        let ts = crate::time::timestamp_millis();
        let csum = checksum64(from, to, data, ts);
        Ok(Self {
            from: String::from(from),
            to: String::from(to),
            data: data.to_vec(),
            timestamp_ms: ts,
            checksum64: csum,
        })
    }

    #[inline]
    pub fn validate_integrity(&self) -> bool {
        self.checksum64 == checksum64(&self.from, &self.to, &self.data, self.timestamp_ms)
    }
}

/// Internal channel registry entry (registered routes are &'static str pairs).
struct ChannelEntry {
    from: &'static str,
    to: &'static str,
    key: u64,
    alive: AtomicBool,
    last_active_ms: AtomicU64,
}

impl ChannelEntry {
    fn new(from: &'static str, to: &'static str) -> Self {
        Self {
            from,
            to,
            key: channel_key(from, to),
            alive: AtomicBool::new(true),
            last_active_ms: AtomicU64::new(crate::time::timestamp_millis()),
        }
    }
}

/// A lightweight handle to a registered route; its send() enqueues on IPC_BUS.
#[derive(Clone, Copy)]
pub struct IpcChannel {
    key: u64,
}

impl IpcChannel {
    #[inline]
    pub fn send(&self, msg: IpcMessage) -> Result<(), &'static str> {
        IPC_BUS.enqueue(self.key, msg)
    }
}

pub struct IpcBus {
    channels: RwLock<Vec<ChannelEntry>>,
    queue: Mutex<VecDeque<(u64, IpcMessage)>>, // (key, message)
    max_queue: usize,
    msg_timeout_ms: u64,
}

impl IpcBus {
    pub const fn new() -> Self {
        Self {
            channels: RwLock::new(Vec::new()),
            queue: Mutex::new(VecDeque::new()),
            max_queue: 4096,
            msg_timeout_ms: 5_000,
        }
    }

    /// Register a new static channel route.
    pub fn open_channel(
        &self,
        from: &'static str,
        to: &'static str,
        _token: &crate::syscall::capabilities::CapabilityToken,
    ) -> Result<(), &'static str> {
        let mut ch = self.channels.write();
        if ch.iter().any(|c| c.from == from && c.to == to) {
            return Ok(());
        }
        ch.push(ChannelEntry::new(from, to));
        Ok(())
    }

    /// Return a handle to a registered channel route.
    pub fn find_channel(&self, from: impl AsRef<str>, to: impl AsRef<str>) -> Option<IpcChannel> {
        let f = from.as_ref();
        let t = to.as_ref();
        let key = channel_key(f, t);
        let ch = self.channels.read();
        if ch.iter().any(|c| c.key == key) {
            Some(IpcChannel { key })
        } else {
            None
        }
    }

    /// Enqueue a message for processing (bounded queue).
    pub fn enqueue(&self, key: u64, msg: IpcMessage) -> Result<(), &'static str> {
        // Update last_active for channel
        if let Some(c) = self.channels.read().iter().find(|c| c.key == key) {
            c.last_active_ms.store(crate::time::timestamp_millis(), Ordering::Relaxed);
            c.alive.store(true, Ordering::Relaxed);
        }

        let mut q = self.queue.lock();
        if q.len() >= self.max_queue {
            return Err("IPC queue full");
        }
        q.push_back((key, msg));
        Ok(())
    }

    /// Pop the next message to process.
    pub fn get_next_message(&self) -> Option<IpcMessage> {
        let mut q = self.queue.lock();
        q.pop_front().map(|(_key, msg)| msg)
    }

    /// Return and remove messages that exceeded timeout.
    pub fn get_timed_out_messages(&self) -> Vec<IpcMessage> {
        let now = crate::time::timestamp_millis();
        let mut q = self.queue.lock();
        let mut out = Vec::new();
        let mut remain = VecDeque::with_capacity(q.len());
        while let Some((key, msg)) = q.pop_front() {
            if now.saturating_sub(msg.timestamp_ms) > self.msg_timeout_ms {
                out.push(msg);
                if let Some(c) = self.channels.read().iter().find(|c| c.key == key) {
                    c.alive.store(false, Ordering::Relaxed);
                }
            } else {
                remain.push_back((key, msg));
            }
        }
        *q = remain;
        out
    }

    /// Find channels marked dead.
    pub fn find_dead_channels(&self) -> Vec<usize> {
        let ch = self.channels.read();
        ch.iter()
            .enumerate()
            .filter(|(_i, c)| !c.alive.load(Ordering::Relaxed))
            .map(|(i, _)| i)
            .collect()
    }

    /// Remove a channel by index.
    pub fn remove_channel(&self, index: usize) {
        let mut ch = self.channels.write();
        if index < ch.len() {
            ch.remove(index);
        }
    }

    /// Remove all channels where module participates.
    pub fn remove_all_channels_for_module(&self, module: &str) {
        let mut ch = self.channels.write();
        ch.retain(|c| c.from != module && c.to != module);
    }

    /// List all routes as (&'static str, &'static str).
    pub fn list_routes(&self) -> alloc::vec::Vec<(&'static str, &'static str)> {
        self.channels
            .read()
            .iter()
            .map(|c| (c.from, c.to))
            .collect()
    }

    /// Channel count.
    pub fn get_active_channel_count(&self) -> usize {
        self.channels.read().len()
    }

    /// Send a system message without capability checks (kernel-originated notifications).
    pub fn send_system_message(&self, env: super::nonos_message::IpcEnvelope) -> Result<(), &'static str> {
        let key = channel_key(&env.from, &env.to);
        let msg = IpcMessage::new(&env.from, &env.to, &env.data)?;
        self.enqueue(key, msg)
    }
}

#[inline]
fn channel_key(from: &str, to: &str) -> u64 {
    // BLAKE3 hash to 64-bit channel key
    let mut hasher = blake3::Hasher::new();
    hasher.update(from.as_bytes());
    hasher.update(&[0]);
    hasher.update(to.as_bytes());
    let out = hasher.finalize();
    let bytes = out.as_bytes();
    u64::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]])
}

#[inline]
fn checksum64(from: &str, to: &str, data: &[u8], ts_ms: u64) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(from.as_bytes());
    hasher.update(&[0xF0]);
    hasher.update(to.as_bytes());
    hasher.update(&ts_ms.to_le_bytes());
    hasher.update(data);
    let out = hasher.finalize();
    let b = out.as_bytes();
    u64::from_le_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]])
}

/// Global IPC bus
pub static IPC_BUS: IpcBus = IpcBus::new();
