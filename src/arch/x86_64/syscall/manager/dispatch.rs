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

use core::sync::atomic::Ordering;

use crate::arch::x86_64::syscall::error::SyscallError;
use crate::arch::x86_64::syscall::stats::SyscallRecord;
use super::core::SyscallManager;

impl SyscallManager {
    pub fn dispatch(&self, number: u64, args: [u64; 6]) -> u64 {
        let start_time = crate::time::now_ns();
        self.stats.total_calls.fetch_add(1, Ordering::Relaxed);

        if let Err(e) = self.validate_syscall(number, &args) {
            self.stats.blocked_calls.fetch_add(1, Ordering::Relaxed);
            self.stats.error_count.fetch_add(1, Ordering::Relaxed);
            return e.to_errno() as u64;
        }

        let handler = {
            let table = self.table.read();
            if let Some(info) = table.get(&number) {
                info.call_count.fetch_add(1, Ordering::Relaxed);
                info.last_called_ns.store(start_time, Ordering::Relaxed);
                info.handler
            } else {
                self.stats.error_count.fetch_add(1, Ordering::Relaxed);
                return SyscallError::HandlerNotFound { number }.to_errno() as u64;
            }
        };

        let result = handler(args[0], args[1], args[2], args[3], args[4], args[5]);

        let end_time = crate::time::now_ns();
        let duration = end_time.saturating_sub(start_time);
        self.stats.total_time_ns.fetch_add(duration, Ordering::Relaxed);

        {
            let table = self.table.read();
            if let Some(info) = table.get(&number) {
                info.total_time_ns.fetch_add(duration, Ordering::Relaxed);
                if (result as i64) < 0 {
                    info.error_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        let config = self.config.read();
        if config.audit_enabled {
            let record = SyscallRecord {
                number,
                args,
                return_value: result,
                timestamp_ns: start_time,
                duration_ns: duration,
                process_id: crate::process::nonos_core::current_pid().unwrap_or(0) as u32,
                thread_id: 0,
                blocked: false,
            };
            drop(config);
            self.add_audit_record(record);
        }

        result
    }

    pub(crate) fn add_audit_record(&self, record: SyscallRecord) {
        let config = self.config.read();
        let max_records = config.max_audit_records;
        drop(config);

        let mut log = self.audit_log.lock();
        if log.len() >= max_records {
            log.remove(0);
        }
        log.push(record);
    }
}
