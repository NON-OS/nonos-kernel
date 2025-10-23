#![no_std]

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{RwLock, Once};

use crate::runtime::nonos_capsule::{Capsule, CapsuleId, CapsuleQuotas, CapsuleState};
use crate::runtime::nonos_isolation::{IsolationPolicy, IsolationState};
use crate::syscall::capabilities::CapabilityToken;

/// Registry holds all capsules and their isolation states
struct Registry {
    by_id: BTreeMap<u64, Arc<Capsule>>,
    by_name: BTreeMap<String, u64>,
    iso: BTreeMap<u64, IsolationState>,
}

impl Registry {
    fn new() -> Self {
        Self {
            by_id: BTreeMap::new(),
            by_name: BTreeMap::new(),
            iso: BTreeMap::new(),
        }
    }
}

static REGISTRY: Once<RwLock<Registry>> = Once::new();
static TICKS: AtomicU64 = AtomicU64::new(0);

fn get_registry() -> &'static RwLock<Registry> {
    REGISTRY.call_once(|| RwLock::new(Registry::new()))
}

/// Create and register a capsule
pub fn register_capsule(
    name: &'static str,
    peers: Vec<&'static str>,
    quotas: CapsuleQuotas,
) -> Arc<Capsule> {
    let cap = Capsule::new(name, peers, quotas.clone());
    let policy = IsolationPolicy {
        inbox_capacity: quotas.inbox_capacity,
        max_msg_bytes: quotas.max_msg_bytes,
        max_bytes_per_sec: quotas.max_bytes_per_sec,
        heartbeat_interval_ms: quotas.heartbeat_interval_ms,
    };
    let iso = IsolationState::new(name, policy);

    {
        let mut reg = get_registry().write();
        reg.by_name.insert(String::from(name), cap.id.get());
        reg.iso.insert(cap.id.get(), iso);
        reg.by_id.insert(cap.id.get(), Arc::clone(&cap));
    }

    crate::drivers::console::write_message(
        &alloc::format!("zerostate: registered capsule '{}' id={}", name, cap.id.get())
    );

    cap
}

/// Start capsule by name
pub fn start_capsule(name: &str, token: &CapabilityToken) -> Result<(), &'static str> {
    let cap = get_capsule_by_name(name).ok_or("capsule not found")?;
    cap.start(token)
}

/// Stop capsule by name
pub fn stop_capsule(name: &str) -> Result<(), &'static str> {
    let cap = get_capsule_by_name(name).ok_or("capsule not found")?;
    cap.stop();
    Ok(())
}

/// Get capsule by name
pub fn get_capsule_by_name(name: &str) -> Option<Arc<Capsule>> {
    let reg = get_registry().read();
    let id = reg.by_name.get(name)?;
    reg.by_id.get(id).cloned()
}

/// Send a payload from capsule to a peer with isolation checks
pub fn send_from_capsule(
    from: &str,
    to: &str,
    payload: &[u8],
    token: &CapabilityToken,
) -> Result<(), &'static str> {
    let (cap, iso) = {
        let reg = get_registry().read();
        let id = reg.by_name.get(from).ok_or("capsule not found")?;
        let cap = reg.by_id.get(id).ok_or("capsule missing")?.clone();
        let iso = reg.iso.get(id).ok_or("isolation missing")?.clone();
        (cap, iso)
    };

    // Isolation checks
    iso.check_inbox_capacity()?;
    iso.charge_message(payload.len())?;

    // Send via capsule
    cap.send(to, payload, token)
}

/// Poll capsule inbox (dequeue one message)
pub fn poll_capsule(name: &str) -> Option<crate::ipc::nonos_channel::IpcMessage> {
    let cap = get_capsule_by_name(name)?;
    cap.recv()
}

/// Update heartbeat for a capsule 
pub fn heartbeat(name: &str) {
    if let Some(cap) = get_capsule_by_name(name) {
        cap.heartbeat();
    }
}

/// Runtime monitor loop. 
pub fn monitor_once() {
    const LOG_EVERY: u64 = 1000; // ms
    let now = crate::time::timestamp_millis();

    let mut warn_list: Vec<&'static str> = Vec::new();
    {
        let reg = get_registry().read();
        for cap in reg.by_id.values() {
            match cap.health() {
                CapsuleState::Running => {}
                CapsuleState::Degraded => warn_list.push(cap.name),
                CapsuleState::Stopped => {}
            }
        }
    }

    if !warn_list.is_empty() {
        crate::drivers::console::write_message(
            &alloc::format!("zerostate: degraded {:?}", warn_list)
        );
    }

    // tick accounting (for optional telemetry)
    let last = TICKS.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= LOG_EVERY {
        TICKS.store(now, Ordering::Relaxed);
    }
}

/// Initialize ZeroState runtime with a kernel capsule and base routes.
/// Safe to call multiple times (idempotent registration).
pub fn init_runtime(token: &CapabilityToken) -> Result<(), &'static str> {
    let kernel = register_capsule(
        "kernel",
        alloc::vec!["kernel"],
        CapsuleQuotas::default(),
    );
    if !kernel_health_running(&kernel) {
        kernel.start(token)?;
    }
  crate::ipc::nonos_inbox::register_inbox("kernel");
  
  crate::drivers::console::write_message(
        "zerostate: runtime online"
    );

    Ok(())
}

fn kernel_health_running(k: &Arc<Capsule>) -> bool {
    matches!(k.health(), CapsuleState::Running)
}
