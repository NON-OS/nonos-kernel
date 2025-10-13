#![no_std]

extern crate alloc;

use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::RwLock;

use crate::ipc::{
    self,
    nonos_inbox as inbox,
    nonos_message::{IpcEnvelope, MessageType, SecurityLevel},
};
use crate::syscall::capabilities::CapabilityToken;

/// Unique ID for a capsule 
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CapsuleId(u64);

impl CapsuleId {
    #[inline]
    pub fn get(&self) -> u64 {
        self.0
    }
}

fn next_capsule_id() -> CapsuleId {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    CapsuleId(NEXT.fetch_add(1, Ordering::Relaxed))
}

/// State of a capsule
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsuleState {
    Stopped,
    Running,
    Degraded, // heartbeat missing but not killed
}

/// Capsule runtime quotas and limits (used by isolation module)
#[derive(Debug, Clone)]
pub struct CapsuleQuotas {
    pub inbox_capacity: usize,
    pub max_msg_bytes: usize,
    pub max_bytes_per_sec: u64,
    pub heartbeat_interval_ms: u64,
}

impl Default for CapsuleQuotas {
    fn default() -> Self {
        Self {
            inbox_capacity: 1024,
            max_msg_bytes: 1 << 20,
            max_bytes_per_sec: 4 << 20,
            heartbeat_interval_ms: 2_000,
        }
    }
}

/// Capsule describes a sandboxed runtime unit that communicates via IPC
pub struct Capsule {
    pub id: CapsuleId,
    pub name: &'static str,
    pub peers: RwLock<Vec<&'static str>>, // allowed peer module names
    pub quotas: CapsuleQuotas,

    running: AtomicBool,
    last_heartbeat_ms: AtomicU64,
}

impl Capsule {
    pub fn new(name: &'static str, peers: Vec<&'static str>, quotas: CapsuleQuotas) -> Arc<Self> {
        Arc::new(Self {
            id: next_capsule_id(),
            name,
            peers: RwLock::new(peers),
            quotas,
            running: AtomicBool::new(false),
            last_heartbeat_ms: AtomicU64::new(0),
        })
    }

    /// Prepare IPC inbox and open secure channels (both directions) for peers.
    pub fn start(&self, token: &CapabilityToken) -> Result<(), &'static str> {
        // Ensure inbox with configured capacity
        crate::ipc::nonos_inbox::set_default_capacity(self.quotas.inbox_capacity);
        inbox::register_inbox(self.name);

        // Open channels to and from peers
        for &peer in self.peers.read().iter() {
            // this -> peer
            let _ = ipc::open_secure_channel(self.name, peer, token)?;
            // peer -> this
            let _ = ipc::open_secure_channel(peer, self.name, token)?;
        }

        self.last_heartbeat_ms
            .store(crate::time::timestamp_millis(), Ordering::Relaxed);
        self.running.store(true, Ordering::Relaxed);

        crate::drivers::console::write_message(
            &alloc::format!("capsule '{}' started (id={})", self.name, self.id.get()),
            crate::drivers::console::LogLevel::Info,
            "runtime",
        );
        Ok(())
    }

    /// Stop capsule 
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        crate::ipc::nonos_channel::IPC_BUS.remove_all_channels_for_module(self.name);
        crate::drivers::console::write_message(
            &alloc::format!("capsule '{}' stopped", self.name),
            crate::drivers::console::LogLevel::Warning,
            "runtime",
        );
    }

    /// Send data to a peer via IPC envelopes (Data message).
    pub fn send(
        &self,
        to: &str,
        data: &[u8],
        token: &CapabilityToken,
    ) -> Result<(), &'static str> {
        // ensure there is a route
        if crate::ipc::nonos_channel::IPC_BUS
            .find_channel(self.name, to)
            .is_none()
        {
            // try open on demand
            let _ = ipc::open_secure_channel(self.name, to, token)?;
        }

        let mut env = IpcEnvelope::new(self.name, to, MessageType::Data, data.to_vec());
        env.sec_level = SecurityLevel::None;
        ipc::send_envelope(env, token)
    }

    /// Receive next message 
    pub fn recv(&self) -> Option<crate::ipc::nonos_channel::IpcMessage> {
        inbox::dequeue(self.name)
    }

    /// Update heartbeat 
    pub fn heartbeat(&self) {
        self.last_heartbeat_ms
            .store(crate::time::timestamp_millis(), Ordering::Relaxed);
    }

    /// Health check 
    pub fn health(&self) -> CapsuleState {
        if !self.running.load(Ordering::Relaxed) {
            return CapsuleState::Stopped;
        }
        let last = self.last_heartbeat_ms.load(Ordering::Relaxed);
        let now = crate::time::timestamp_millis();
        if now.saturating_sub(last) > self.quotas.heartbeat_interval_ms * 2 {
            CapsuleState::Degraded
        } else {
            CapsuleState::Running
        }
    }
}
