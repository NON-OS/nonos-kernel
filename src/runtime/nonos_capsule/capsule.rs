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

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::RwLock;

use crate::ipc::{
    self,
    nonos_inbox as inbox,
    nonos_message::{IpcEnvelope, MessageType, SecurityLevel},
};
use crate::syscall::capabilities::CapabilityToken;

use super::types::{CapsuleId, CapsuleQuotas, CapsuleState, next_capsule_id};

pub struct Capsule {
    pub id: CapsuleId,
    pub name: &'static str,
    pub peers: RwLock<Vec<&'static str>>,
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

    pub fn start(&self, token: &CapabilityToken) -> Result<(), &'static str> {
        crate::ipc::nonos_inbox::set_default_capacity(self.quotas.inbox_capacity);
        inbox::register_inbox(self.name);

        for &peer in self.peers.read().iter() {
            let _ = ipc::open_secure_channel(self.name, peer, token)?;
            let _ = ipc::open_secure_channel(peer, self.name, token)?;
        }

        self.last_heartbeat_ms
            .store(crate::time::timestamp_millis(), Ordering::Relaxed);
        self.running.store(true, Ordering::Relaxed);

        crate::drivers::console::write_message(
            &alloc::format!("capsule '{}' started (id={})", self.name, self.id.get())
        );
        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        crate::ipc::nonos_channel::IPC_BUS.remove_all_channels_for_module(self.name);
        crate::drivers::console::write_message(
            &alloc::format!("capsule '{}' stopped", self.name)
        );
    }

    pub fn send(
        &self,
        to: &'static str,
        data: &[u8],
        token: &CapabilityToken,
    ) -> Result<(), &'static str> {
        if crate::ipc::nonos_channel::IPC_BUS
            .find_channel(self.name, to)
            .is_none()
        {
            let _ = ipc::open_secure_channel(self.name, to, token)?;
        }

        let mut env = IpcEnvelope::new(self.name, to, MessageType::Data, data.to_vec());
        env.sec_level = SecurityLevel::None;
        ipc::send_envelope(env, token)
    }

    pub fn recv(&self) -> Option<crate::ipc::nonos_channel::IpcMessage> {
        inbox::dequeue(self.name)
    }

    pub fn heartbeat(&self) {
        self.last_heartbeat_ms
            .store(crate::time::timestamp_millis(), Ordering::Relaxed);
    }

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
