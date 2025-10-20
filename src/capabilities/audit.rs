#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::capabilities::{CapabilityToken, Capability};

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub owner_module: u64,
    pub action: &'static str,
    pub capability: Option<Capability>,
    pub nonce: u64,
    pub result: bool,
}

const MAX_LOG: usize = 4096;

static LOG: Mutex<Vec<AuditEntry>> = Mutex::new(Vec::new());
static LOG_INDEX: AtomicUsize = AtomicUsize::new(0);

pub fn log_use(token: &CapabilityToken, action: &'static str, cap: Option<Capability>, result: bool) {
    let entry = AuditEntry {
        timestamp: crate::time::timestamp_millis(),
        owner_module: token.owner_module,
        action,
        capability: cap,
        nonce: token.nonce,
        result,
    };
    let mut log = LOG.lock();
    if log.len() < MAX_LOG {
        log.push(entry);
    } else {
        let idx = LOG_INDEX.fetch_add(1, Ordering::Relaxed) % MAX_LOG;
        log[idx] = entry;
    }
}

pub fn get_log() -> Vec<AuditEntry> {
    LOG.lock().clone()
}
