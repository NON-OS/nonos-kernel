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

use super::keystore::{self, KeyType};
use core::sync::atomic::{AtomicU64, Ordering};

static TICK_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Run the keyring service
pub fn run_keyring_service() -> ! {
    crate::services::registry::register_endpoint_simple("keyring", 1023, 23);
    crate::sys::boot_log::ok("KEYRING", "Service ready");

    loop {
        // Handle IPC requests
        handle_keyring_requests();

        // Periodic cleanup every 1000 ticks
        let tick = TICK_COUNTER.fetch_add(1, Ordering::Relaxed);
        if tick % 1000 == 0 {
            keystore::cleanup_expired_keys();
        }

        crate::sched::yield_now();
    }
}

fn handle_keyring_requests() {
    if let Some(msg) = crate::ipc::nonos_inbox::try_dequeue("keyring") {
        let sender_pid = msg.from.parse::<u32>().unwrap_or(0);
        let response = process_request(&msg.data, sender_pid);
        if let Ok(reply) =
            crate::ipc::nonos_channel::IpcMessage::new("keyring", &msg.from, &response)
        {
            let _ = crate::ipc::nonos_inbox::try_enqueue(&msg.from, reply);
        }
    }
}

fn process_request(data: &[u8], sender_pid: u32) -> [u8; 300] {
    let mut response = [0u8; 300];

    if data.is_empty() {
        return response;
    }

    match data[0] {
        // Store key
        0x01 => {
            if data.len() >= 12 {
                let key_type = match data[1] {
                    0 => KeyType::Symmetric,
                    1 => KeyType::PrivateKey,
                    2 => KeyType::PublicKey,
                    3 => KeyType::HmacSecret,
                    4 => KeyType::DerivedKey,
                    5 => KeyType::SessionKey,
                    6 => KeyType::MasterKey,
                    7 => KeyType::SigningKey,
                    _ => {
                        response[0] = 0xFE; // Invalid type
                        return response;
                    }
                };
                let expires_at = u64::from_le_bytes([
                    data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
                ]);
                let key_len = u16::from_le_bytes([data[10], data[11]]) as usize;
                if data.len() >= 12 + key_len {
                    let key_data = &data[12..12 + key_len];
                    if let Some(id) =
                        keystore::store_key(key_type, key_data, sender_pid, expires_at)
                    {
                        response[0] = 0x01; // Success
                        response[1..5].copy_from_slice(&id.to_le_bytes());
                    } else {
                        response[0] = 0x03; // Store failed
                    }
                } else {
                    response[0] = 0x02; // Invalid length
                }
            }
        }
        // Retrieve key
        0x02 => {
            if data.len() >= 5 {
                let id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                let mut key_buf = [0u8; 256];
                if let Some(size) = keystore::retrieve_key(id, sender_pid, &mut key_buf) {
                    response[0] = 0x01; // Success
                    response[1..3].copy_from_slice(&(size as u16).to_le_bytes());
                    response[3..3 + size].copy_from_slice(&key_buf[..size]);
                } else {
                    response[0] = 0x04; // Not found or access denied
                }
            }
        }
        // Delete key
        0x03 => {
            if data.len() >= 5 {
                let id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                if keystore::delete_key(id, sender_pid) {
                    response[0] = 0x01; // Success
                } else {
                    response[0] = 0x04; // Not found or access denied
                }
            }
        }
        // Lock key
        0x04 => {
            if data.len() >= 5 {
                let id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                if keystore::lock_key(id, sender_pid) {
                    response[0] = 0x01;
                } else {
                    response[0] = 0x04;
                }
            }
        }
        // Unlock key
        0x05 => {
            if data.len() >= 5 {
                let id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                if keystore::unlock_key(id, sender_pid) {
                    response[0] = 0x01;
                } else {
                    response[0] = 0x04;
                }
            }
        }
        // Get key metadata
        0x06 => {
            if data.len() >= 5 {
                let id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                if let Some(meta) = keystore::get_key_metadata(id) {
                    response[0] = 0x01;
                    response[1..5].copy_from_slice(&meta.id.to_le_bytes());
                    response[5] = meta.key_type as u8;
                    response[6..8].copy_from_slice(&(meta.size as u16).to_le_bytes());
                    response[8..12].copy_from_slice(&meta.owner_pid.to_le_bytes());
                    response[12..20].copy_from_slice(&meta.created_at.to_le_bytes());
                    response[20..28].copy_from_slice(&meta.expires_at.to_le_bytes());
                    response[28..36].copy_from_slice(&meta.use_count.to_le_bytes());
                    response[36] = if meta.locked { 1 } else { 0 };
                } else {
                    response[0] = 0x04;
                }
            }
        }
        // Get key count
        0x10 => {
            response[0] = 0x01;
            let count = keystore::key_count();
            response[1..5].copy_from_slice(&(count as u32).to_le_bytes());
        }
        _ => {
            response[0] = 0xFF; // Unknown command
        }
    }

    response
}
