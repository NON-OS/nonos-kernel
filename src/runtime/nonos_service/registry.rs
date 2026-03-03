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

use alloc::{boxed::Box, collections::BTreeMap, string::String};
use spin::{RwLock, Once};

use crate::runtime::nonos_zerostate::send_from_capsule;
use crate::syscall::capabilities::CapabilityToken;

struct ServiceRegistry {
    map: BTreeMap<String, String>,
}

impl ServiceRegistry {
    fn new() -> Self {
        Self { map: BTreeMap::new() }
    }
}

static REGISTRY: Once<RwLock<ServiceRegistry>> = Once::new();

fn get_registry() -> &'static RwLock<ServiceRegistry> {
    REGISTRY.call_once(|| RwLock::new(ServiceRegistry::new()))
}

pub fn bind(service: &str, capsule: &str) {
    let mut r = get_registry().write();
    r.map.insert(service.into(), capsule.into());
    crate::drivers::console::write_message(
        &alloc::format!("service: '{}' -> '{}'", service, capsule)
    );
}

pub fn unbind(service: &str) {
    let mut r = get_registry().write();
    r.map.remove(service);
}

pub fn resolve(service: &str) -> Option<String> {
    get_registry().read().map.get(service).cloned()
}

pub fn send_to_service(
    from_capsule: &str,
    service: &str,
    payload: &[u8],
    token: &CapabilityToken,
) -> Result<(), &'static str> {
    let Some(target_capsule) = resolve(service) else {
        return Err("service not found");
    };
    let target_capsule_static: &'static str = Box::leak(target_capsule.into_boxed_str());
    send_from_capsule(from_capsule, target_capsule_static, payload, token)
}
