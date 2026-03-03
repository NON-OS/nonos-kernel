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

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::runtime::nonos_capsule::{Capsule, CapsuleQuotas, CapsuleState};
use crate::syscall::capabilities::CapabilityToken;

use super::registry::get_registry;
use super::capsule_ops::register_capsule;

static TICKS: AtomicU64 = AtomicU64::new(0);

pub fn monitor_once() {
    const LOG_EVERY: u64 = 1000;
    let now = crate::time::timestamp_millis();

    let mut warn_list: Vec<&'static str> = Vec::new();
    {
        let reg = get_registry().read();
        for cap in reg.by_id.values() {
            match cap.health() {
                CapsuleState::Running => {}
                CapsuleState::Degraded => warn_list.push(cap.name),
                CapsuleState::Stopped => {}
            }
        }
    }

    if !warn_list.is_empty() {
        crate::drivers::console::write_message(
            &alloc::format!("zerostate: degraded {:?}", warn_list)
        );
    }

    let last = TICKS.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= LOG_EVERY {
        TICKS.store(now, Ordering::Relaxed);
    }
}

pub fn init_runtime(token: &CapabilityToken) -> Result<(), &'static str> {
    let kernel = register_capsule(
        "kernel",
        alloc::vec!["kernel"],
        CapsuleQuotas::default(),
    );
    if !kernel_health_running(&kernel) {
        kernel.start(token)?;
    }
    crate::ipc::nonos_inbox::register_inbox("kernel");

    crate::drivers::console::write_message("zerostate: runtime online");

    Ok(())
}

fn kernel_health_running(k: &Arc<Capsule>) -> bool {
    matches!(k.health(), CapsuleState::Running)
}
