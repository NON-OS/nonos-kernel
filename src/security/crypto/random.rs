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

use core::sync::atomic::{AtomicU64, Ordering};

static RANDOM_COUNTER: AtomicU64 = AtomicU64::new(1);

pub fn init() -> Result<(), &'static str> {
    Ok(())
}

pub fn secure_random_u64() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let mut value: u64 = 0;
        unsafe {
            if core::arch::x86_64::_rdrand64_step(&mut value) == 1 {
                return value;
            }
        }
    }
    let ctr = RANDOM_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tsc = unsafe { core::arch::x86_64::_rdtsc() };
    tsc ^ ctr ^ 0xA5A5_5A5A_DEAD_BEEF
}

pub fn fill_random(buf: &mut [u8]) {
    let mut off = 0;
    while off < buf.len() {
        let v = secure_random_u64();
        let chunk = v.to_le_bytes();
        let remain = buf.len() - off;
        let take = core::cmp::min(remain, chunk.len());
        buf[off..off+take].copy_from_slice(&chunk[..take]);
        off += take;
    }
}

pub fn secure_random_u32() -> u32 {
    secure_random_u64() as u32
}

pub fn secure_random_u8() -> u8 {
    secure_random_u64() as u8
}
