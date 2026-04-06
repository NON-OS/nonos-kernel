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

pub fn read_pid_stat(pid: i32) -> Result<String, i32> {
    let proc = crate::process::get_process(pid).ok_or(-3)?;
    let state = match proc.state {
        crate::process::ProcessState::Running => 'R',
        crate::process::ProcessState::Sleeping => 'S',
        crate::process::ProcessState::Stopped => 'T',
        crate::process::ProcessState::Zombie => 'Z',
        crate::process::ProcessState::Dead => 'X',
    };
    let mem = proc.memory_info;
    let time = proc.time_info;
    Ok(format!(
        "{} ({}) {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}\n",
        pid, proc.name, state, proc.ppid, proc.pgid, proc.sid,
        proc.tty_nr, proc.tty_pgrp, proc.flags,
        mem.minflt, mem.cminflt, mem.majflt, mem.cmajflt,
        time.utime, time.stime, time.cutime, time.cstime,
        proc.priority, proc.nice, proc.thread_count, 0i64,
        time.start_time, mem.vsize, mem.rss,
        mem.rsslim, mem.startcode, mem.endcode, mem.startstack,
        proc.kstkesp, proc.kstkeip, proc.signals.pending,
        proc.signals.blocked, proc.signals.ignored, proc.signals.caught,
        proc.wchan, 0u64, 0u64, proc.exit_signal, proc.processor,
        proc.rt_priority, proc.policy, time.delayacct_blkio_ticks,
        time.guest_time, time.cguest_time,
        mem.start_data, mem.end_data, mem.start_brk, mem.arg_start, mem.arg_end,
        mem.env_start, mem.env_end, proc.exit_code
    ))
}

pub fn parse_pid_stat(content: &str) -> Option<PidStatInfo> {
    let parts: alloc::vec::Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 52 { return None; }
    Some(PidStatInfo {
        pid: parts[0].parse().ok()?,
        comm: parts[1].trim_matches(|c| c == '(' || c == ')').into(),
        state: parts[2].chars().next()?,
        ppid: parts[3].parse().ok()?,
        utime: parts[13].parse().ok()?,
        stime: parts[14].parse().ok()?,
        vsize: parts[22].parse().ok()?,
        rss: parts[23].parse().ok()?,
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
