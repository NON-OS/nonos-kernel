#![no_std]

extern crate alloc;

use alloc::{collections::BTreeMap, string::String};
use spin::{RwLock, Once};

use crate::runtime::nonos_zerostate::send_from_capsule;
use crate::syscall::capabilities::CapabilityToken;

/// Service registry maps a service name to a target capsule name.
struct SvcReg {
    map: BTreeMap<String, String>, // service -> capsule
}

impl SvcReg {
    fn new() -> Self { Self { map: BTreeMap::new() } }
}

static REG: Once<RwLock<SvcReg>> = Once::new();

fn get_reg() -> &'static RwLock<SvcReg> {
    REG.call_once(|| RwLock::new(SvcReg::new()))
}

/// Bind a service name to a capsule.
pub fn bind(service: &str, capsule: &str) {
    let mut r = get_reg().write();
    r.map.insert(service.into(), capsule.into());
    crate::drivers::console::write_message(
        &alloc::format!("service: '{}' -> '{}'", service, capsule)
    );
}

/// Unbind a service.
pub fn unbind(service: &str) {
    let mut r = get_reg().write();
    r.map.remove(service);
}

/// Resolve a service to a capsule name.
pub fn resolve(service: &str) -> Option<String> {
    get_reg().read().map.get(service).cloned()
}

/// Send payload from a capsule to a service.
pub fn send_to_service(from_capsule: &str, service: &str, payload: &[u8], token: &CapabilityToken) -> Result<(), &'static str> {
    let Some(target_capsule) = resolve(service) else { return Err("service not found"); };
    send_from_capsule(from_capsule, &target_capsule, payload, token)
}
