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

use spin::Once;

const DS_IPC_SECRET: &str = "NONOS:IPC:SECRET:v1";
const DS_CHANNEL_KEY: &str = "NONOS:IPC:CHANNEL:v1";
const DS_MSG_MAC: &str = "NONOS:IPC:MAC:v1";

static IPC_SECRET: Once<[u8; 32]> = Once::new();

// Must be called after `crypto::util::rng::init_rng` has succeeded.
// Returns `Err` if the RNG fails to fill 32 bytes; the caller is
// expected to treat that as fatal so an all-zero MAC key never gets
// derived.
pub fn init_ipc_secret() -> Result<(), &'static str> {
    let mut bytes = [0u8; 32];
    if crate::crypto::random_api::get_bytes_secure(&mut bytes).is_err() {
        return Err("rng failed to seed IPC MAC key");
    }
    let derived =
        *blake3::Hasher::new_derive_key(DS_IPC_SECRET).update(&bytes).finalize().as_bytes();
    IPC_SECRET.call_once(|| derived);
    Ok(())
}

#[inline]
fn get_ipc_secret() -> &'static [u8; 32] {
    IPC_SECRET
        .get()
        .expect("init_ipc_secret was never called; IPC MAC key uninitialised")
}

#[inline]
pub fn compute_channel_key(from: &str, to: &str) -> u64 {
    let secret = get_ipc_secret();
    let h = blake3::Hasher::new_derive_key(DS_CHANNEL_KEY)
        .update(secret)
        .update(from.as_bytes())
        .update(&[0x00])
        .update(to.as_bytes())
        .finalize();
    u64::from_le_bytes([
        h.as_bytes()[0],
        h.as_bytes()[1],
        h.as_bytes()[2],
        h.as_bytes()[3],
        h.as_bytes()[4],
        h.as_bytes()[5],
        h.as_bytes()[6],
        h.as_bytes()[7],
    ])
}

#[inline]
pub fn compute_checksum(from: &str, to: &str, data: &[u8], ts_ms: u64) -> u64 {
    let secret = get_ipc_secret();
    let mac = blake3::Hasher::new_keyed(secret)
        .update(DS_MSG_MAC.as_bytes())
        .update(from.as_bytes())
        .update(&[0xF0])
        .update(to.as_bytes())
        .update(&ts_ms.to_le_bytes())
        .update(data)
        .finalize();
    let b = mac.as_bytes();
    u64::from_le_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]])
}

#[inline]
pub(super) fn verify_checksum(
    from: &str,
    to: &str,
    data: &[u8],
    ts_ms: u64,
    expected: u64,
) -> bool {
    let computed = compute_checksum(from, to, data, ts_ms);
    let mut diff = 0u64;
    diff |= computed ^ expected;
    diff == 0
}
