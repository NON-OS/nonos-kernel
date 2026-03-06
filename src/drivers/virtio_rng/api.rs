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
use super::{VIRTIO_RNG, VIRTIO_RNG_AVAILABLE};

#[inline]
pub fn is_available() -> bool {
    VIRTIO_RNG_AVAILABLE.load(Ordering::Acquire)
}

pub fn get_random_bytes(buf: &mut [u8]) -> Result<usize, &'static str> {
    if !is_available() {
        return Err("virtio-rng not available");
    }

    let mut guard = VIRTIO_RNG.lock();
    let dev = guard.as_mut().ok_or("virtio-rng not initialized")?;
    dev.get_random_bytes(buf)
}

pub fn fill_random(buf: &mut [u8]) -> Result<(), &'static str> {
    if buf.is_empty() {
        return Ok(());
    }

    let mut filled = 0;
    let mut attempts = 0;

    while filled < buf.len() && attempts < 100 {
        match get_random_bytes(&mut buf[filled..]) {
            Ok(n) => {
                filled += n;
                if n == 0 {
                    attempts += 1;
                    for _ in 0..100 {
                        core::hint::spin_loop();
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }

    if filled < buf.len() {
        Err("virtio-rng: timeout waiting for entropy")
    } else {
        Ok(())
    }
}
