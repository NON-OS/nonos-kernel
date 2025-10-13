#![no_std]

extern crate alloc;

use alloc::{collections::{BTreeMap, VecDeque}, string::String, sync::Arc};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

use super::nonos_channel::IpcMessage;

/// Per-module inbox entry
pub struct Inbox {
    queue: Mutex<VecDeque<IpcMessage>>,
    cap: usize,
}

impl Inbox {
    fn new(cap: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(cap)),
            cap,
        }
    }

    #[inline]
    fn is_full(&self) -> bool {
        let q = self.queue.lock();
        q.len() >= self.cap
    }

    fn enqueue_with_timeout(&self, msg: IpcMessage, timeout_ms: u64) -> Result<(), &'static str> {
        let start = crate::time::timestamp_millis();
        loop {
            {
                let mut q = self.queue.lock();
                if q.len() < self.cap {
                    q.push_back(msg);
                    return Ok(());
                }
            }
            if crate::time::timestamp_millis().saturating_sub(start) >= timeout_ms {
                return Err("inbox full (timeout)");
            }
            // short backoff spin
            for _ in 0..256 {
                core::hint::spin_loop();
            }
        }
    }

    #[inline]
    fn dequeue(&self) -> Option<IpcMessage> {
        self.queue.lock().pop_front()
    }

    #[inline]
    fn len(&self) -> usize {
        self.queue.lock().len()
    }
}

struct Registry {
    map: BTreeMap<String, Arc<Inbox>>,
}

impl Registry {
    fn new() -> Self {
        Self { map: BTreeMap::new() }
    }
}

static REGISTRY: RwLock<Registry> = RwLock::new(Registry::new());
static DEFAULT_CAP: AtomicUsize = AtomicUsize::new(1024);

/// Set default inbox capacity (affects future registrations)
pub fn set_default_capacity(cap: usize) {
    DEFAULT_CAP.store(core::cmp::max(16, cap), Ordering::Relaxed);
}

pub fn register_inbox(module: &str) {
    let cap = DEFAULT_CAP.load(Ordering::Relaxed);
    let mut reg = REGISTRY.write();
    if !reg.map.contains_key(module) {
        reg.map.insert(module.into(), Arc::new(Inbox::new(cap)));
    }
}

pub fn is_full(module: &str) -> bool {
    let reg = REGISTRY.read();
    if let Some(inbox) = reg.map.get(module) {
        inbox.is_full()
    } else {
        false
    }
}

/// Enqueue with timeout semantics on a module’s inbox.
/// Auto-registers inbox if missing.
pub fn enqueue_with_timeout(module: &str, msg: IpcMessage, timeout_ms: u64) -> Result<(), &'static str> {
    register_inbox(module);
    let reg = REGISTRY.read();
    let inbox = reg.map.get(module).ok_or("inbox not found")?;
    inbox.enqueue_with_timeout(msg, timeout_ms)
}

pub fn dequeue(module: &str) -> Option<IpcMessage> {
    register_inbox(module);
    let reg = REGISTRY.read();
    reg.map.get(module).and_then(|i| i.dequeue())
}

/// Current inbox length for a module (0 if not registered)
pub fn len(module: &str) -> usize {
    let reg = REGISTRY.read();
    reg.map.get(module).map(|i| i.len()).unwrap_or(0)
}
