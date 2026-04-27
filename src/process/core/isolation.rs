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

use alloc::collections::BTreeMap;
use core::sync::atomic::Ordering;
use spin::RwLock;
use x86_64::VirtAddr;

use super::table::PROCESS_TABLE;
use super::types::{IsolationFlags, Pid, ProcessState, Vma};

static PROCESS_ISOLATION: RwLock<BTreeMap<Pid, IsolationFlags>> = RwLock::new(BTreeMap::new());

pub fn isolate_process(pid: Pid) -> Result<(), &'static str> {
    let pcb = PROCESS_TABLE.find_by_pid(pid).ok_or("Process not found")?;

    let state = *pcb.state.lock();
    match state {
        ProcessState::Terminated(_) | ProcessState::Zombie(_) => {
            return Err("Cannot isolate terminated process");
        }
        _ => {}
    }

    let isolation = IsolationFlags::default();

    const NETWORK_CAP: u64 = 1 << 10;
    const RAW_DISK_CAP: u64 = 1 << 11;
    const IPC_ADMIN_CAP: u64 = 1 << 12;
    const DEVICE_CAP: u64 = 1 << 13;
    const DANGEROUS_CAPS: u64 = NETWORK_CAP | RAW_DISK_CAP | IPC_ADMIN_CAP | DEVICE_CAP;

    let old_caps = pcb.caps_bits.load(Ordering::SeqCst);
    let new_caps = old_caps & !DANGEROUS_CAPS;
    pcb.caps_bits.store(new_caps, Ordering::SeqCst);

    PROCESS_ISOLATION.write().insert(pid, isolation);

    {
        let mem = pcb.memory.lock();
        for vma in &mem.vmas {
            mark_vma_isolated(vma)?;
        }
    }

    crate::log_info!("Process {} isolated: capabilities reduced", pid);
    Ok(())
}

fn mark_vma_isolated(vma: &Vma) -> Result<(), &'static str> {
    let pages = ((vma.end.as_u64() - vma.start.as_u64()) as usize + 4095) / 4096;
    for i in 0..pages {
        let page_va = VirtAddr::new(vma.start.as_u64() + (i as u64) * 4096);
        crate::memory::paging::update_page_flags(
            page_va,
            crate::memory::paging::PagePermissions::USER,
        )
        .map_err(|_| "Failed to update page flags")?;
    }
    Ok(())
}

pub fn is_process_isolated(pid: Pid) -> bool {
    PROCESS_ISOLATION.read().contains_key(&pid)
}

pub fn get_isolation_flags(pid: Pid) -> Option<IsolationFlags> {
    PROCESS_ISOLATION.read().get(&pid).copied()
}

pub fn unisolate_process(pid: Pid) -> Result<(), &'static str> {
    let pcb = PROCESS_TABLE.find_by_pid(pid).ok_or("Process not found")?;

    if *pcb.state.lock() == crate::process::ProcessState::Terminated(0) {
        return Err("Cannot unisolate terminated process");
    }

    if PROCESS_ISOLATION.write().remove(&pid).is_none() {
        return Err("Process was not isolated");
    }

    crate::log_info!("Process {} isolation removed", pid);
    Ok(())
}

pub fn check_isolated_capability(pid: Pid, capability: u64) -> bool {
    if let Some(isolation) = get_isolation_flags(pid) {
        const NETWORK_CAP: u64 = 1 << 10;
        const RAW_DISK_CAP: u64 = 1 << 11;
        const IPC_ADMIN_CAP: u64 = 1 << 12;
        const DEVICE_CAP: u64 = 1 << 13;

        if isolation.no_network && (capability & NETWORK_CAP) != 0 {
            return false;
        }
        if isolation.no_filesystem && (capability & RAW_DISK_CAP) != 0 {
            return false;
        }
        if isolation.no_ipc && (capability & IPC_ADMIN_CAP) != 0 {
            return false;
        }
        if isolation.no_devices && (capability & DEVICE_CAP) != 0 {
            return false;
        }
    }
    true
}

pub fn can_signal_process(sender_pid: Pid, target_pid: Pid) -> bool {
    if sender_pid == target_pid {
        return true;
    }
    if is_process_isolated(target_pid) {
        if let Some(flags) = get_isolation_flags(target_pid) {
            if flags.no_signals {
                return false;
            }
        }
    }
    if is_process_isolated(sender_pid) {
        if let Some(flags) = get_isolation_flags(sender_pid) {
            if flags.no_signals {
                return false;
            }
        }
    }
    true
}

pub fn can_access_shared_memory(pid: Pid, shmid: i32) -> bool {
    if is_process_isolated(pid) {
        if let Some(flags) = get_isolation_flags(pid) {
            if flags.no_ipc {
                crate::security::monitoring::audit::log_security_event(
                    "isolation",
                    crate::security::monitoring::audit::AuditSeverity::Warning,
                    alloc::format!("Isolated process {} denied shm access to {}", pid, shmid),
                    Some(pid as u64),
                    None,
                    None,
                );
                return false;
            }
        }
    }
    true
}

pub fn can_ptrace_process(tracer_pid: Pid, tracee_pid: Pid) -> bool {
    if is_process_isolated(tracee_pid) {
        crate::security::monitoring::audit::log_security_event(
            "isolation",
            crate::security::monitoring::audit::AuditSeverity::Warning,
            alloc::format!("Ptrace denied: {} -> isolated {}", tracer_pid, tracee_pid),
            Some(tracer_pid as u64),
            None,
            None,
        );
        return false;
    }
    if is_process_isolated(tracer_pid) {
        return false;
    }
    true
}

pub fn enforce_isolation_on_exec(pid: Pid) {
    if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
        const ALL_DANGEROUS_CAPS: u64 =
            (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 15);
        pcb.caps_bits.fetch_and(!ALL_DANGEROUS_CAPS, Ordering::SeqCst);
        crate::security::monitoring::audit::log_security_event(
            "isolation",
            crate::security::monitoring::audit::AuditSeverity::Info,
            alloc::format!("Capabilities reduced on exec for isolated process {}", pid),
            Some(pid as u64),
            None,
            None,
        );
    }
}
