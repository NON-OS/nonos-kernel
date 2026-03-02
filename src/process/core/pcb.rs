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

use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

use super::types::{Pid, ProcessState, Priority, MemoryState};
use super::thread_group::ThreadGroup;

#[derive(Debug)]
pub struct ProcessControlBlock {
    pub pid: Pid,
    pub tgid: AtomicU32,
    pub ppid: AtomicU32,
    pub pgid: AtomicU32,
    pub sid: AtomicU32,
    pub name: Mutex<String>,
    pub state: Mutex<ProcessState>,
    pub priority: Mutex<Priority>,
    pub memory: Mutex<MemoryState>,
    pub thread_group: Option<Arc<ThreadGroup>>,
    pub argv: Mutex<Vec<String>>,
    pub envp: Mutex<Vec<String>>,
    pub caps_bits: AtomicU64,
    pub exit_code: AtomicI32,
    pub zk_proofs_generated: AtomicU64,
    pub zk_proving_time_ms: AtomicU64,
    pub zk_proofs_verified: AtomicU64,
    pub zk_verification_time_ms: AtomicU64,
    pub zk_circuits_compiled: AtomicU64,
    pub umask: Mutex<u32>,
    pub root_dir: Mutex<String>,
    pub clear_child_tid: AtomicU64,
    pub set_child_tid: AtomicU64,
    pub alarm_time_ms: AtomicU64,
    pub tls_base: AtomicU64,
    pub stack_base: AtomicU64,
    pub clone_flags: AtomicU64,
    pub start_time_ms: AtomicU64,
}

impl ProcessControlBlock {
    #[inline]
    pub fn terminate(&self, code: i32) {
        self.exit_code.store(code, Ordering::Relaxed);
        *self.state.lock() = ProcessState::Terminated(code);
    }

    #[inline]
    pub fn parent_pid(&self) -> Pid {
        self.ppid.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn process_group(&self) -> Pid {
        self.pgid.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn exit_status(&self) -> i32 {
        self.exit_code.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn capability_token(&self) -> crate::syscall::capabilities::CapabilityToken {
        let bits = self.caps_bits.load(Ordering::Relaxed);
        let mut token_data = [0u8; 72];
        token_data[..8].copy_from_slice(&bits.to_le_bytes());

        let kernel_keypair = crate::crypto::ed25519::KeyPair { public: [0u8; 32], private: [0u8; 32] };
        let sig = crate::crypto::ed25519::sign(&kernel_keypair, &token_data[..8]);
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&sig.R);
        signature[32..].copy_from_slice(&sig.S);

        crate::syscall::capabilities::CapabilityToken {
            owner_module: self.pid as u64,
            permissions: alloc::vec![crate::capabilities::Capability::CoreExec],
            expires_at_ms: Some(crate::time::timestamp_millis() + 86400000),
            nonce: bits,
            signature,
        }
    }

    pub fn set_name(&self, new_name: &str) {
        let mut name = self.name.lock();
        name.clear();
        let truncated = if new_name.len() > 256 { &new_name[..256] } else { new_name };
        name.push_str(truncated);
    }

    pub fn get_name(&self) -> String {
        self.name.lock().clone()
    }

    pub fn set_clear_child_tid(&self, tidptr: u64) {
        self.clear_child_tid.store(tidptr, Ordering::Release);
    }

    pub fn get_clear_child_tid(&self) -> u64 {
        self.clear_child_tid.load(Ordering::Acquire)
    }

    pub fn set_alarm(&self, seconds: u32) -> u32 {
        let now_ms = crate::time::timestamp_millis();
        let old_alarm_ms = self.alarm_time_ms.load(Ordering::Acquire);

        let remaining = if old_alarm_ms > now_ms {
            ((old_alarm_ms - now_ms) / 1000) as u32
        } else {
            0
        };

        let new_alarm_ms = if seconds == 0 {
            0
        } else {
            now_ms.saturating_add((seconds as u64) * 1000)
        };
        self.alarm_time_ms.store(new_alarm_ms, Ordering::Release);

        remaining
    }

    pub fn check_alarm_expired(&self) -> bool {
        let alarm_ms = self.alarm_time_ms.load(Ordering::Acquire);
        if alarm_ms == 0 {
            return false;
        }
        let now_ms = crate::time::timestamp_millis();
        if now_ms >= alarm_ms {
            self.alarm_time_ms.store(0, Ordering::Release);
            true
        } else {
            false
        }
    }

    #[inline]
    pub fn pid(&self) -> Pid {
        self.pid
    }

    #[inline]
    pub fn thread_group_id(&self) -> Pid {
        self.tgid.load(Ordering::Acquire)
    }

    #[inline]
    pub fn name(&self) -> String {
        self.get_name()
    }

    #[inline]
    pub fn session_id(&self) -> Pid {
        self.sid.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn is_thread(&self) -> bool {
        self.thread_group.as_ref()
            .map(|tg| tg.thread_count() > 1 || self.pid != tg.tgid)
            .unwrap_or(false)
    }

    #[inline]
    pub fn is_group_leader(&self) -> bool {
        self.thread_group.as_ref()
            .map(|tg| tg.is_leader(self.pid))
            .unwrap_or(true)
    }

    #[inline]
    pub fn get_tls_base(&self) -> u64 {
        self.tls_base.load(Ordering::Acquire)
    }

    #[inline]
    pub fn set_tls_base(&self, base: u64) {
        self.tls_base.store(base, Ordering::Release);
    }

    #[inline]
    pub fn get_stack_base(&self) -> u64 {
        self.stack_base.load(Ordering::Acquire)
    }

    #[inline]
    pub fn set_stack_base(&self, base: u64) {
        self.stack_base.store(base, Ordering::Release);
    }

    pub fn on_thread_exit(&self) {
        let clear_tid_ptr = self.clear_child_tid.load(Ordering::Acquire);
        if clear_tid_ptr != 0 {
            // SAFETY: Pointer set by process via CLONE_CHILD_CLEARTID.
            unsafe {
                let ptr = clear_tid_ptr as *mut u32;
                if ptr.is_aligned() {
                    core::ptr::write_volatile(ptr, 0);
                }
            }
        }

        if let Some(ref tg) = self.thread_group {
            tg.remove_thread(self.pid);
        }
    }
}
