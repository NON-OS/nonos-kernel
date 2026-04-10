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

#[derive(Debug, Clone, Copy, Default)]
pub struct CapsuleStats {
    pub cpu_ns: u64,
    pub mem_peak: u64,
    pub mem_current: u64,
    pub syscalls: u64,
    pub ipc_sent: u64,
    pub ipc_recv: u64,
    pub net_tx: u64,
    pub net_rx: u64,
    pub started_at: u64,
    pub duration_ns: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct GlobalStats {
    pub active_capsules: u64,
    pub total_launched: u64,
    pub total_exited: u64,
    pub total_faulted: u64,
    pub total_cpu_ns: u64,
    pub total_mem_used: u64,
}

impl CapsuleStats {
    pub fn new(started_at: u64) -> Self { Self { started_at, ..Default::default() } }
    pub fn add_cpu(&mut self, ns: u64) { self.cpu_ns += ns; }
    pub fn add_syscall(&mut self) { self.syscalls += 1; }
    pub fn add_ipc_sent(&mut self) { self.ipc_sent += 1; }
    pub fn add_ipc_recv(&mut self) { self.ipc_recv += 1; }
    pub fn add_net_tx(&mut self, bytes: u64) { self.net_tx += bytes; }
    pub fn add_net_rx(&mut self, bytes: u64) { self.net_rx += bytes; }

    pub fn update_mem(&mut self, current: u64) {
        self.mem_current = current;
        if current > self.mem_peak { self.mem_peak = current; }
    }

    pub fn finalize(&mut self, ended_at: u64) {
        self.duration_ns = ended_at.saturating_sub(self.started_at);
    }
}

impl GlobalStats {
    pub fn capsule_started(&mut self) { self.active_capsules += 1; self.total_launched += 1; }
    pub fn capsule_exited(&mut self) { self.active_capsules = self.active_capsules.saturating_sub(1); self.total_exited += 1; }
    pub fn capsule_faulted(&mut self) { self.active_capsules = self.active_capsules.saturating_sub(1); self.total_faulted += 1; }
}
