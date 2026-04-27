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

use crate::process::ProcessState;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::Ordering;

pub fn read_pid_status(pid: i32) -> Result<String, i32> {
    let proc = crate::process::get_process(pid as u32).ok_or(-3)?;
    let state_guard = proc.state.lock();
    let state = match *state_guard {
        ProcessState::Running => "R (running)",
        ProcessState::Sleeping => "S (sleeping)",
        ProcessState::Stopped => "T (stopped)",
        ProcessState::Zombie(_) => "Z (zombie)",
        ProcessState::Terminated(_) => "X (dead)",
        ProcessState::New => "N (new)",
        ProcessState::Ready => "R (ready)",
    };
    drop(state_guard);

    let name = proc.name.lock().clone();
    let umask = *proc.umask.lock();
    let ppid = proc.ppid.load(Ordering::Relaxed);
    let pgid = proc.pgid.load(Ordering::Relaxed);
    let sid = proc.sid.load(Ordering::Relaxed);
    let tgid = proc.tgid.load(Ordering::Relaxed);
    let thread_count = proc.thread_count.load(Ordering::Relaxed);

    let creds = proc.creds.lock();
    let signals = proc.signals.lock();
    let caps = proc.caps.lock();
    let mem_info = proc.memory_info.lock();

    Ok(format!(
        "Name:\t{}\nUmask:\t{:04o}\nState:\t{}\nTgid:\t{}\nNgid:\t0\nPid:\t{}\nPPid:\t{}\nTracerPid:\t0\n\
Uid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nFDSize:\t64\nGroups:\t\nNStgid:\t{}\nNSpid:\t{}\nNSpgid:\t{}\nNSsid:\t{}\n\
VmPeak:\t{:>8} kB\nVmSize:\t{:>8} kB\nVmLck:\t{:>8} kB\nVmPin:\t{:>8} kB\n\
VmHWM:\t{:>8} kB\nVmRSS:\t{:>8} kB\nRssAnon:\t{:>8} kB\nRssFile:\t{:>8} kB\nRssShmem:\t{:>8} kB\n\
VmData:\t{:>8} kB\nVmStk:\t{:>8} kB\nVmExe:\t{:>8} kB\nVmLib:\t{:>8} kB\nVmPTE:\t{:>8} kB\nVmSwap:\t{:>8} kB\n\
Threads:\t{}\nSigPnd:\t{:016x}\nShdPnd:\t{:016x}\nSigBlk:\t{:016x}\nSigIgn:\t{:016x}\nSigCgt:\t{:016x}\n\
CapInh:\t{:016x}\nCapPrm:\t{:016x}\nCapEff:\t{:016x}\nCapBnd:\t{:016x}\nCapAmb:\t{:016x}\n",
        name, umask, state, tgid, pid, ppid,
        creds.uid, creds.euid, creds.suid, creds.fsuid, creds.gid, creds.egid, creds.sgid, creds.fsgid,
        tgid, pid, pgid, sid,
        mem_info.vm_peak / 1024, mem_info.vm_size / 1024, 0, 0,
        mem_info.vm_hwm / 1024, mem_info.vm_rss / 1024, mem_info.rss_anon / 1024, mem_info.rss_file / 1024, mem_info.rss_shmem / 1024,
        mem_info.vm_data / 1024, mem_info.vm_stack / 1024, mem_info.vm_exe / 1024, mem_info.vm_lib / 1024, mem_info.vm_pte / 1024, 0,
        thread_count, signals.pending, signals.shared_pending, signals.blocked, signals.ignored, signals.caught,
        caps.inheritable, caps.permitted, caps.effective, caps.bounding, caps.ambient
    ))
}
