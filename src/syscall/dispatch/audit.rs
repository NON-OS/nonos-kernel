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

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use crate::syscall::{SyscallNumber, SyscallResult};

pub static AUDIT_ENABLED: AtomicBool = AtomicBool::new(true);
pub static AUDIT_VERBOSE: AtomicBool = AtomicBool::new(false);

pub static SYSCALL_STATS: SyscallStats = SyscallStats::new();

pub struct SyscallStats {
    pub total_calls: AtomicU64,
    pub successful_calls: AtomicU64,
    pub failed_calls: AtomicU64,
    pub permission_denied: AtomicU64,
    pub audit_entries: AtomicU64,
}

impl SyscallStats {
    pub const fn new() -> Self {
        Self {
            total_calls: AtomicU64::new(0),
            successful_calls: AtomicU64::new(0),
            failed_calls: AtomicU64::new(0),
            permission_denied: AtomicU64::new(0),
            audit_entries: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SyscallAuditEntry {
    pub timestamp_ms: u64,
    pub syscall_num: u64,
    pub syscall_name: &'static str,
    pub pid: u32,
    pub result: i64,
    pub args: [u64; 4],
    pub success: bool,
}

pub static AUDIT_LOG: Mutex<AuditLog> = Mutex::new(AuditLog::new());

pub struct AuditLog {
    entries: [Option<SyscallAuditEntry>; 256],
    head: usize,
    count: usize,
}

impl AuditLog {
    pub const fn new() -> Self {
        const NONE: Option<SyscallAuditEntry> = None;
        Self { entries: [NONE; 256], head: 0, count: 0 }
    }

    pub fn push(&mut self, entry: SyscallAuditEntry) {
        self.entries[self.head] = Some(entry);
        self.head = (self.head + 1) % 256;
        if self.count < 256 {
            self.count += 1;
        }
    }
}

fn syscall_name(syscall: SyscallNumber) -> &'static str {
    match syscall {
        SyscallNumber::CryptoRandom => "CryptoRandom",
        SyscallNumber::CryptoHash => "CryptoHash",
        SyscallNumber::CryptoSign => "CryptoSign",
        SyscallNumber::CryptoVerify => "CryptoVerify",
        SyscallNumber::CryptoEncrypt => "CryptoEncrypt",
        SyscallNumber::CryptoDecrypt => "CryptoDecrypt",
        SyscallNumber::CryptoKeyGen => "CryptoKeyGen",
        SyscallNumber::CryptoZkProve => "CryptoZkProve",
        SyscallNumber::CryptoZkVerify => "CryptoZkVerify",
        SyscallNumber::CryptoEd25519Verify => "CryptoEd25519Verify",
        SyscallNumber::IoPortRead => "IoPortRead",
        SyscallNumber::IoPortWrite => "IoPortWrite",
        SyscallNumber::MmioMap => "MmioMap",
        SyscallNumber::DebugLog => "DebugLog",
        SyscallNumber::DebugTrace => "DebugTrace",
        SyscallNumber::AdminReboot => "AdminReboot",
        SyscallNumber::AdminShutdown => "AdminShutdown",
        SyscallNumber::AdminModLoad => "AdminModLoad",
        SyscallNumber::AdminCapGrant => "AdminCapGrant",
        SyscallNumber::AdminCapRevoke => "AdminCapRevoke",
        SyscallNumber::GraphicsDisplayDimensions => "GraphicsDisplayDimensions",
        SyscallNumber::GraphicsSurfaceCreate => "GraphicsSurfaceCreate",
        SyscallNumber::GraphicsSurfaceDestroy => "GraphicsSurfaceDestroy",
        SyscallNumber::GraphicsSurfaceMap => "GraphicsSurfaceMap",
        SyscallNumber::GraphicsSurfacePresentFull => "GraphicsSurfacePresentFull",
        SyscallNumber::GraphicsSurfacePresentRect => "GraphicsSurfacePresentRect",
        SyscallNumber::GraphicsDisplayList => "GraphicsDisplayList",
        SyscallNumber::GraphicsCursorPresent => "GraphicsCursorPresent",
        SyscallNumber::MkIpcSend => "MkIpcSend",
        SyscallNumber::MkIpcRecv => "MkIpcRecv",
        SyscallNumber::MkIpcCall => "MkIpcCall",
        SyscallNumber::MkMmap => "MkMmap",
        SyscallNumber::MkMunmap => "MkMunmap",
        SyscallNumber::MkSpawn => "MkSpawn",
        SyscallNumber::MkExit => "MkExit",
        SyscallNumber::MkYield => "MkYield",
        SyscallNumber::MkCapGrant => "MkCapGrant",
        SyscallNumber::MkCapRevoke => "MkCapRevoke",
        SyscallNumber::MkCapCheck => "MkCapCheck",
        SyscallNumber::MkDeviceList => "MkDeviceList",
        SyscallNumber::MkDeviceClaim => "MkDeviceClaim",
        SyscallNumber::MkDeviceRelease => "MkDeviceRelease",
        SyscallNumber::MkMmioMap => "MkMmioMap",
        SyscallNumber::MkMmioUnmap => "MkMmioUnmap",
        SyscallNumber::MkIrqBind => "MkIrqBind",
        SyscallNumber::MkIrqUnbind => "MkIrqUnbind",
        SyscallNumber::MkIrqAck => "MkIrqAck",
        SyscallNumber::MkIrqPoll => "MkIrqPoll",
        SyscallNumber::MkDmaMap => "MkDmaMap",
        SyscallNumber::MkDmaUnmap => "MkDmaUnmap",
        SyscallNumber::MkPioGrant => "MkPioGrant",
        SyscallNumber::MkPioRead => "MkPioRead",
        SyscallNumber::MkPioWrite => "MkPioWrite",
        SyscallNumber::MkPioRelease => "MkPioRelease",
        SyscallNumber::MkDebug => "MkDebug",
    }
}

pub fn audit_syscall(syscall: SyscallNumber, args: [u64; 4], result: &SyscallResult) {
    if !AUDIT_ENABLED.load(Ordering::Relaxed) {
        return;
    }

    let name = syscall_name(syscall);
    let pid = crate::process::current_process().map(|p| p.pid).unwrap_or(0);

    let entry = SyscallAuditEntry {
        timestamp_ms: crate::time::timestamp_millis(),
        syscall_num: syscall as u64,
        syscall_name: name,
        pid,
        result: result.value,
        args,
        success: result.value >= 0,
    };

    if AUDIT_VERBOSE.load(Ordering::Relaxed) {
        crate::log::info!(
            "syscall: {}({:x},{:x},{:x},{:x}) = {} [pid={}]",
            name,
            args[0],
            args[1],
            args[2],
            args[3],
            result.value,
            pid
        );
    }

    let mut log = AUDIT_LOG.lock();
    log.push(entry);
    SYSCALL_STATS.audit_entries.fetch_add(1, Ordering::Relaxed);
}

pub fn set_audit_enabled(enabled: bool) {
    AUDIT_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn set_audit_verbose(verbose: bool) {
    AUDIT_VERBOSE.store(verbose, Ordering::Relaxed);
}

pub fn get_syscall_stats() -> (u64, u64, u64, u64) {
    (
        SYSCALL_STATS.total_calls.load(Ordering::Relaxed),
        SYSCALL_STATS.successful_calls.load(Ordering::Relaxed),
        SYSCALL_STATS.failed_calls.load(Ordering::Relaxed),
        SYSCALL_STATS.permission_denied.load(Ordering::Relaxed),
    )
}

pub fn get_audit_log(max_entries: usize) -> alloc::vec::Vec<SyscallAuditEntry> {
    let log = AUDIT_LOG.lock();
    let mut result = alloc::vec::Vec::with_capacity(max_entries.min(log.count));

    let start = if log.count >= 256 { log.head } else { 0 };

    for i in 0..log.count.min(max_entries) {
        let idx = (start + log.count - 1 - i) % 256;
        if let Some(entry) = &log.entries[idx] {
            result.push(entry.clone());
        }
    }

    result
}

pub fn clear_audit_log() {
    let mut log = AUDIT_LOG.lock();
    *log = AuditLog::new();
}
