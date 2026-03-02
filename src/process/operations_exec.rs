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

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::core::{current_process, ProcessControlBlock, ProcessState, PROCESS_TABLE};

pub fn exec_process(path: &str, argv: &[String], envp: &[String]) -> Result<(), &'static str> {
    let current = current_process().ok_or("no current process")?;

    let executable_data = crate::fs::read_file(path)?;

    let entry_point = match crate::elf::minimal::entry_from_bytes(&executable_data) {
        Ok(ep) => ep,
        Err(_) => return Err("invalid executable format"),
    };

    if entry_point == 0 {
        return Err("executable has no entry point");
    }

    {
        let mut name = current.name.lock();
        *name = path.into();
    }

    {
        let mut current_argv = current.argv.lock();
        current_argv.clear();
        current_argv.reserve(argv.len());
        for arg in argv {
            current_argv.push(arg.clone());
        }
    }

    {
        let mut current_envp = current.envp.lock();
        current_envp.clear();
        current_envp.reserve(envp.len());
        for env in envp {
            current_envp.push(env.clone());
        }
    }

    {
        let mut state = current.state.lock();
        *state = ProcessState::Ready;
    }

    Ok(())
}

#[inline]
pub fn exec_fn(path: &str) -> Result<(), &'static str> {
    exec_process(path, &[], &[])
}

pub fn set_umask(mask: u32) -> u32 {
    let current = match current_process() {
        Some(p) => p,
        None => return 0o022,
    };

    let mut umask = current.umask.lock();
    let old_mask = *umask;
    *umask = mask;
    old_mask
}

pub fn set_root(path: &str) -> Result<(), &'static str> {
    let current = current_process().ok_or("no current process")?;

    if !crate::fs::is_directory(path) {
        return Err("not a directory");
    }

    let mut root = current.root_dir.lock();
    *root = String::from(path);
    Ok(())
}

pub fn update_memory_usage(process_id: u64, delta: i64) {
    if let Some(pcb) = PROCESS_TABLE.find_by_pid(process_id as u32) {
        let memory = pcb.memory.lock();
        let pages = ((delta.unsigned_abs() + 4095) / 4096) as u64;

        if delta > 0 {
            memory.resident_pages.fetch_add(pages, Ordering::Relaxed);
        } else if delta < 0 {
            memory.resident_pages.fetch_sub(pages, Ordering::Relaxed);
        }

        let current_pages = memory.resident_pages.load(Ordering::Relaxed);
        if delta.abs() > 1024 * 1024 {
            crate::log::info!(
                "Process {} memory usage: {} pages (delta: {} bytes)",
                process_id,
                current_pages,
                delta
            );
        }
    }
}

pub fn exit_current_process(status: i32) -> ! {
    if let Some(pcb) = current_process() {
        pcb.on_thread_exit();
    }
    super::core::syscalls::sys_exit(status)
}

pub fn exit_thread(status: i32) -> ! {
    if let Some(pcb) = current_process() {
        pcb.on_thread_exit();

        let is_last_thread = pcb.thread_group.as_ref()
            .map(|tg| tg.thread_count() <= 1)
            .unwrap_or(true);

        if is_last_thread || pcb.is_group_leader() {
            super::core::syscalls::sys_exit(status);
        }

        pcb.exit_code.store(status, Ordering::Release);
        {
            let mut state = pcb.state.lock();
            *state = ProcessState::Terminated(status);
        }
    }

    loop {
        x86_64::instructions::hlt();
    }
}

pub fn get_thread_count() -> u32 {
    current_process()
        .and_then(|pcb| pcb.thread_group.as_ref().map(|tg| tg.thread_count()))
        .unwrap_or(1)
}

pub fn get_thread_ids() -> Vec<u32> {
    current_process()
        .and_then(|pcb| pcb.thread_group.as_ref().map(|tg| tg.threads.read().clone()))
        .unwrap_or_else(|| {
            current_process().map(|p| vec![p.pid]).unwrap_or_default()
        })
}

#[inline]
pub fn get_current_process() -> Option<Arc<ProcessControlBlock>> {
    current_process()
}

#[inline]
pub fn get_current_process_capabilities() -> super::capabilities::CapabilitySet {
    if let Some(pcb) = current_process() {
        let bits = pcb.caps_bits.load(Ordering::Acquire);
        super::capabilities::CapabilitySet::from_bits(bits)
    } else {
        super::capabilities::CapabilitySet::from_bits(u64::MAX)
    }
}

pub fn enumerate_all_processes() -> Vec<super::types::Process> {
    super::core::get_process_table()
        .get_all_processes()
        .into_iter()
        .map(|pcb| {
            let name = pcb.name.lock().clone();
            super::types::Process::new(pcb.pid, name, Some(pcb))
        })
        .collect()
}

#[inline]
pub fn get_all_processes() -> Vec<super::types::Process> {
    enumerate_all_processes()
}
