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
use alloc::format;

pub fn read_pid_status(pid: i32) -> Result<String, i32> {
    let proc = crate::process::get_process(pid).ok_or(-3)?;
    let state = match proc.state {
        crate::process::ProcessState::Running => "R (running)",
        crate::process::ProcessState::Sleeping => "S (sleeping)",
        crate::process::ProcessState::Stopped => "T (stopped)",
        crate::process::ProcessState::Zombie => "Z (zombie)",
        crate::process::ProcessState::Dead => "X (dead)",
    };
    let mem = proc.memory_info;
    Ok(format!(
        "Name:\t{}\nUmask:\t{:04o}\nState:\t{}\nTgid:\t{}\nNgid:\t{}\nPid:\t{}\nPPid:\t{}\nTracerPid:\t{}\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nFDSize:\t{}\nGroups:\t{}\nNStgid:\t{}\nNSpid:\t{}\nNSpgid:\t{}\nNSsid:\t{}\nVmPeak:\t{:>8} kB\nVmSize:\t{:>8} kB\nVmLck:\t{:>8} kB\nVmPin:\t{:>8} kB\nVmHWM:\t{:>8} kB\nVmRSS:\t{:>8} kB\nRssAnon:\t{:>8} kB\nRssFile:\t{:>8} kB\nRssShmem:\t{:>8} kB\nVmData:\t{:>8} kB\nVmStk:\t{:>8} kB\nVmExe:\t{:>8} kB\nVmLib:\t{:>8} kB\nVmPTE:\t{:>8} kB\nVmSwap:\t{:>8} kB\nHugetlbPages:\t{:>8} kB\nCoreDumping:\t{}\nTHP_enabled:\t{}\nThreads:\t{}\nSigQ:\t{}/{}\nSigPnd:\t{:016x}\nShdPnd:\t{:016x}\nSigBlk:\t{:016x}\nSigIgn:\t{:016x}\nSigCgt:\t{:016x}\nCapInh:\t{:016x}\nCapPrm:\t{:016x}\nCapEff:\t{:016x}\nCapBnd:\t{:016x}\nCapAmb:\t{:016x}\nNoNewPrivs:\t{}\nSeccomp:\t{}\nSeccomp_filters:\t{}\nSpeculation_Store_Bypass:\t{}\nSpeculationIndirectBranch:\t{}\nCpus_allowed:\t{:x}\nCpus_allowed_list:\t{}\nMems_allowed:\t{:x}\nMems_allowed_list:\t{}\nvoluntary_ctxt_switches:\t{}\nnonvoluntary_ctxt_switches:\t{}\n",
        proc.name, proc.umask, state, pid, 0, pid, proc.ppid, 0,
        proc.uid, proc.euid, proc.suid, proc.fsuid, proc.gid, proc.egid, proc.sgid, proc.fsgid,
        proc.fd_count, "", pid, pid, proc.pgid, proc.sid,
        mem.vm_peak / 1024, mem.vm_size / 1024, 0, 0, mem.vm_hwm / 1024, mem.vm_rss / 1024,
        mem.rss_anon / 1024, mem.rss_file / 1024, mem.rss_shmem / 1024,
        mem.vm_data / 1024, mem.vm_stack / 1024, mem.vm_exe / 1024, mem.vm_lib / 1024, mem.vm_pte / 1024, 0, 0,
        0, 1, proc.thread_count, proc.pending_signals, 128,
        proc.signals.pending, proc.signals.shared_pending, proc.signals.blocked, proc.signals.ignored, proc.signals.caught,
        proc.caps.inheritable, proc.caps.permitted, proc.caps.effective, proc.caps.bounding, proc.caps.ambient,
        proc.no_new_privs as u8, proc.seccomp, 0, "not vulnerable", "conditional enabled", proc.cpus_allowed, "0-3", 1, "0",
        proc.voluntary_switches, proc.involuntary_switches
    ))
}
