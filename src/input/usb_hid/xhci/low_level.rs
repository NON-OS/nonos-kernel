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

#[inline]
pub(crate) unsafe fn mr32(a: u64) -> u32 {
    unsafe { core::ptr::read_volatile(a as *const u32) }
}

#[inline]
pub(crate) unsafe fn mw32(a: u64, v: u32) {
    unsafe {
        core::ptr::write_volatile(a as *mut u32, v);
    }
}

#[inline]
pub(crate) unsafe fn mw64(a: u64, v: u64) {
    unsafe {
        core::ptr::write_volatile(a as *mut u64, v);
    }
}

pub(crate) fn spin(n: u32) {
    for _ in 0..n {
        core::hint::spin_loop();
    }
}

#[inline]
pub(crate) fn coop_tick(i: u32) {
    spin(1);
    if i & 0xFF == 0 {
        crate::sched::yield_now();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn yield_mask_hits_every_256_iters() {
        let mut hits = 0u32;
        for i in 0..1024u32 {
            if i & 0xFF == 0 {
                hits += 1;
            }
        }
        assert_eq!(hits, 4);
    }
}
