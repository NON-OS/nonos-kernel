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

use super::pool;
use core::sync::atomic::{AtomicU64, Ordering};

/// Tick counter for periodic entropy collection
static TICK_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Run the entropy pool service
pub fn run_entropy_service() -> ! {
    pool::init_pool();
    crate::services::registry::register_endpoint_simple("entropy", 1022, 22);
    crate::sys::boot_log::ok("ENTROPY", "Service ready");

    loop {
        // Periodically collect hardware entropy
        let tick = TICK_COUNTER.fetch_add(1, Ordering::Relaxed);
        if tick % 50 == 0 {
            pool::add_hardware_entropy();
        }

        // Handle IPC requests
        handle_entropy_requests();

        crate::sched::yield_now();
    }
}

fn handle_entropy_requests() {
    if let Some(msg) = crate::ipc::nonos_inbox::try_dequeue("entropy") {
        let response = process_request(&msg.data);
        if let Ok(reply) =
            crate::ipc::nonos_channel::IpcMessage::new("entropy", &msg.from, &response)
        {
            let _ = crate::ipc::nonos_inbox::try_enqueue(&msg.from, reply);
        }
    }
}

fn process_request(data: &[u8]) -> [u8; 256] {
    let mut response = [0u8; 256];

    if data.is_empty() {
        return response;
    }

    match data[0] {
        // Get random bytes (non-blocking)
        0x01 => {
            let len = if data.len() >= 2 { core::cmp::min(data[1] as usize, 200) } else { 32 };
            if pool::get_random_bytes(&mut response[2..2 + len]) {
                response[0] = 0x01; // Success
                response[1] = len as u8;
            } else {
                response[0] = 0x02; // Insufficient entropy
            }
        }
        // Add entropy
        0x02 => {
            if data.len() >= 3 {
                let bits = data[1] as u64;
                let entropy_data = &data[2..];
                pool::add_entropy(entropy_data, bits);
                response[0] = 0x01; // Success
            }
        }
        // Get entropy available
        0x03 => {
            response[0] = 0x01;
            let bits = pool::get_entropy_available();
            response[1..9].copy_from_slice(&bits.to_le_bytes());
        }
        0x04 => {
            let len = if data.len() >= 2 { core::cmp::min(data[1] as usize, 200) } else { 32 };
            pool::get_random_bytes_blocking(&mut response[2..2 + len]);
            response[0] = 0x01;
            response[1] = len as u8;
        }
        0x05 => {
            if data.len() >= 10 {
                let irq = data[1];
                let timestamp = u64::from_le_bytes([
                    data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
                ]);
                pool::add_interrupt_entropy(irq, timestamp);
                response[0] = 0x01;
            }
        }
        0x10 => {
            let stats = pool::get_stats();
            response[0] = 0x01;
            response[1..9].copy_from_slice(&stats.entropy_bits.to_le_bytes());
            response[9..17].copy_from_slice(&stats.bytes_extracted.to_le_bytes());
            response[17..25].copy_from_slice(&stats.bits_added.to_le_bytes());
            response[25..33].copy_from_slice(&stats.reseed_count.to_le_bytes());
        }
        _ => {
            response[0] = 0xFF; // Unknown command
        }
    }

    response
}
