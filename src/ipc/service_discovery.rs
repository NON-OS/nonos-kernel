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
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::{Mutex, Once};

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub endpoint: String,
    pub capabilities: u64,
    pub process_id: u64,
    pub security_level: super::SecurityLevel,
}

static SERVICE_REGISTRY: Once<Mutex<BTreeMap<String, ServiceInfo>>> = Once::new();

pub fn register_service(service: ServiceInfo) -> Result<(), super::IpcError> {
    let registry = SERVICE_REGISTRY.call_once(|| Mutex::new(BTreeMap::new()));
    registry.lock().insert(service.name.clone(), service);
    Ok(())
}

pub fn discover_service(name: &str) -> Option<ServiceInfo> {
    SERVICE_REGISTRY.get()?.lock().get(name).cloned()
}

pub fn list_services() -> Vec<ServiceInfo> {
    SERVICE_REGISTRY
        .get()
        .map(|registry| registry.lock().values().cloned().collect())
        .unwrap_or_default()
}

pub fn unregister_service(name: &str) -> Result<(), super::IpcError> {
    if let Some(registry) = SERVICE_REGISTRY.get() {
        registry.lock().remove(name);
    }
    Ok(())
}

pub fn find_services_by_capability(capability_mask: u64) -> Vec<ServiceInfo> {
    SERVICE_REGISTRY
        .get()
        .map(|registry| {
            registry
                .lock()
                .values()
                .filter(|service| service.capabilities & capability_mask != 0)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}
