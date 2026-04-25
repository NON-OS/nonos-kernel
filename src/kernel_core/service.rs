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

use alloc::{string::String, vec::Vec};
use spin::Mutex;

pub type ServiceId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ServiceState {
    Registered = 0,
    Starting = 1,
    Running = 2,
    Stopping = 3,
    Stopped = 4,
    Failed = 5,
}

#[derive(Debug, Clone)]
pub struct ServiceDescriptor {
    pub id: ServiceId,
    pub name: String,
    pub state: ServiceState,
    pub pid: Option<u32>,
    pub ipc_port: Option<u32>,
    pub required_caps: u64,
}

impl ServiceDescriptor {
    pub fn new(id: ServiceId, name: String, caps: u64) -> Self {
        Self {
            id,
            name,
            state: ServiceState::Registered,
            pid: None,
            ipc_port: None,
            required_caps: caps,
        }
    }
}

pub static SERVICE_REGISTRY: Mutex<Vec<ServiceDescriptor>> = Mutex::new(Vec::new());

pub fn register_service(name: String, caps: u64) -> ServiceId {
    let mut reg = SERVICE_REGISTRY.lock();
    let id = reg.len() as ServiceId;
    reg.push(ServiceDescriptor::new(id, name, caps));
    id
}

pub fn get_service(id: ServiceId) -> Option<ServiceDescriptor> {
    SERVICE_REGISTRY.lock().get(id as usize).cloned()
}

pub fn update_state(id: ServiceId, state: ServiceState) {
    if let Some(svc) = SERVICE_REGISTRY.lock().get_mut(id as usize) {
        svc.state = state;
    }
}

pub fn set_pid(id: ServiceId, pid: u32) {
    if let Some(svc) = SERVICE_REGISTRY.lock().get_mut(id as usize) {
        svc.pid = Some(pid);
    }
}
