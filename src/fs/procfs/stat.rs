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

use alloc::format;
use alloc::string::String;

pub fn read_stat() -> String {
    let stats = crate::sched::get_cpu_stats();
    let num_cpus = crate::smp::cpu_count();
    let mut output = String::new();
    let (user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice) = stats.total();
    output.push_str(&format!(
        "cpu  {} {} {} {} {} {} {} {} {} {}\n",
        user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice
    ));
    let per_cpu = stats.per_cpu();
    for cpu in 0..num_cpus {
        let s = per_cpu.get(cpu).cloned().unwrap_or_default();
        output.push_str(&format!(
            "cpu{} {} {} {} {} {} {} {} {} {} {}\n",
            cpu,
            s.user_time,
            0,
            s.system_time,
            s.idle_time,
            s.iowait_time,
            s.irq_time,
            s.softirq_time,
            s.steal_time,
            s.guest_time,
            s.guest_nice_time
        ));
    }
    let intr_stats = crate::interrupts::get_interrupt_stats();
    output.push_str(&format!("intr {}", intr_stats.total));
    for i in 0..256 {
        output.push_str(&format!(" {}", intr_stats.per_irq.get(i).unwrap_or(&0)));
    }
    output.push('\n');
    output.push_str(&format!("ctxt {}\n", stats.context_switches));
    output.push_str(&format!("btime {}\n", crate::sys::clock::boot_time_secs()));
    output.push_str(&format!("processes {}\n", stats.processes_created));
    output.push_str(&format!("procs_running {}\n", stats.procs_running));
    output.push_str(&format!("procs_blocked {}\n", stats.procs_blocked));
    let softirq_stats = crate::interrupts::get_softirq_stats();
    output.push_str(&format!("softirq {}", softirq_stats.total));
    for i in 0..10 {
        output.push_str(&format!(" {}", softirq_stats.per_type.get(i).unwrap_or(&0)));
    }
    output.push('\n');
    output
}
