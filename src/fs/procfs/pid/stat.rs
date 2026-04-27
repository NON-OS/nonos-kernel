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

pub fn read_pid_stat(pid: i32) -> Result<String, i32> {
    let proc = crate::process::get_process(pid as u32).ok_or(-3)?;
    let state_guard = proc.state.lock();
    let state = match *state_guard {
        ProcessState::Running | ProcessState::Ready => 'R',
        ProcessState::Sleeping => 'S',
        ProcessState::Stopped => 'T',
        ProcessState::Zombie(_) => 'Z',
        ProcessState::Terminated(_) => 'X',
        ProcessState::New => 'N',
    };
    drop(state_guard);

    let name = proc.name.lock().clone();
    let ppid = proc.ppid.load(Ordering::Relaxed);
    let pgid = proc.pgid.load(Ordering::Relaxed);
    let sid = proc.sid.load(Ordering::Relaxed);
    let tty_nr = proc.tty_nr.load(Ordering::Relaxed);
    let tty_pgrp = proc.tty_pgrp.load(Ordering::Relaxed);
    let flags = proc.flags.load(Ordering::Relaxed);
    let nice = proc.nice.load(Ordering::Relaxed);
    let thread_count = proc.thread_count.load(Ordering::Relaxed);
    let processor = proc.processor.load(Ordering::Relaxed);
    let rt_priority = proc.rt_priority.load(Ordering::Relaxed);
    let policy = proc.policy.load(Ordering::Relaxed);
    let exit_signal = proc.exit_signal.load(Ordering::Relaxed);
    let kstkesp = proc.kstkesp.load(Ordering::Relaxed);
    let kstkeip = proc.kstkeip.load(Ordering::Relaxed);
    let wchan = proc.wchan.load(Ordering::Relaxed);

    let time_info = proc.time_info.lock();
    let mem_info = proc.memory_info.lock();
    let signals = proc.signals.lock();
    let priority = proc.priority.lock();
    let prio_val = match *priority {
        crate::process::Priority::Idle => 19,
        crate::process::Priority::Low => 10,
        crate::process::Priority::Normal => 0,
        crate::process::Priority::High => -10,
        crate::process::Priority::RealTime => -20,
    };

    Ok(format!(
        "{} ({}) {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}\n",
        pid, name, state, ppid, pgid, sid, tty_nr, tty_pgrp, flags,
        mem_info.minflt, mem_info.cminflt, mem_info.majflt, mem_info.cmajflt,
        time_info.utime, time_info.stime, time_info.cutime, time_info.cstime,
        prio_val, nice, thread_count, 0i64,
        time_info.start_time, mem_info.vsize, mem_info.vm_rss / 4096,
        mem_info.rsslim, mem_info.startcode, mem_info.endcode, mem_info.startstack,
        kstkesp, kstkeip, signals.pending, signals.blocked, signals.ignored, signals.caught,
        wchan, 0u64, 0u64, exit_signal, processor, rt_priority, policy,
        time_info.delayacct_blkio_ticks, time_info.guest_time, time_info.cguest_time,
        mem_info.start_data, mem_info.end_data, mem_info.start_brk,
        mem_info.arg_start, mem_info.arg_end, mem_info.env_start, mem_info.env_end,
        proc.exit_code.load(Ordering::Relaxed)
    ))
}

pub fn parse_pid_stat(content: &str) -> Option<PidStatInfo> {
    let parts: alloc::vec::Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 24 {
        return None;
    }
    Some(PidStatInfo {
        pid: parts[0].parse().ok()?,
        comm: parts[1].trim_matches(|c| c == '(' || c == ')').into(),
        state: parts[2].chars().next()?,
        ppid: parts[3].parse().ok()?,
        utime: parts.get(13).and_then(|s| s.parse().ok()).unwrap_or(0),
        stime: parts.get(14).and_then(|s| s.parse().ok()).unwrap_or(0),
        vsize: parts.get(22).and_then(|s| s.parse().ok()).unwrap_or(0),
        rss: parts.get(23).and_then(|s| s.parse().ok()).unwrap_or(0),
    })
}

pub struct PidStatInfo {
    pub pid: i32,
    pub comm: String,
    pub state: char,
    pub ppid: i32,
    pub utime: u64,
    pub stime: u64,
    pub vsize: u64,
    pub rss: i64,
}
