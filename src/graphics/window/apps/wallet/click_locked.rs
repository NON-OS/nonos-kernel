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

use super::state::*;

pub(super) fn handle_locked_click(x: u32, y: u32, w: u32, h: u32) -> bool {
    let center_x: u32 = w / 2;
    let center_y: u32 = h / 2;

    let field_x1 = center_x.saturating_sub(120);
    let field_x2 = center_x + 120;
    let field_y1 = center_y + 5;
    let field_y2 = center_y + 33;

    if x >= field_x1 && x <= field_x2 && y >= field_y1 && y <= field_y2 {
        PASSWORD_FOCUSED.store(true, Ordering::SeqCst);
        return true;
    }

    let btn_x1 = center_x.saturating_sub(60);
    let btn_x2 = center_x + 60;
    let btn_y1 = center_y + 50;
    let btn_y2 = center_y + 82;

    if x >= btn_x1 && x <= btn_x2 && y >= btn_y1 && y <= btn_y2 {
        try_unlock();
        return true;
    }

    let new_btn_x1 = center_x.saturating_sub(60);
    let new_btn_x2 = center_x + 60;
    let new_btn_y1 = center_y + 90;
    let new_btn_y2 = center_y + 118;

    if x >= new_btn_x1 && x <= new_btn_x2 && y >= new_btn_y1 && y <= new_btn_y2 {
        generate_new_wallet();
        return true;
    }

    PASSWORD_FOCUSED.store(false, Ordering::SeqCst);
    false
}

fn generate_new_wallet() {
    use crate::crypto::blake3_hash;
    use crate::crypto::util::rng;
    use crate::drivers::{virtio_rng, tpm};
    use core::sync::atomic::{AtomicU64, Ordering as AO};

    static WALLET_CTR: AtomicU64 = AtomicU64::new(0xCAFE_BABE_0000_0001);

    lock_wallet();

    let ctr = WALLET_CTR.fetch_add(0x0001_0001_0001_0001, AO::SeqCst);

    let mut e = [0u8; 256];

    if virtio_rng::is_available() {
        let _ = virtio_rng::fill_random(&mut e);
    } else if tpm::is_tpm_available() {
        if let Ok(bytes) = tpm::get_random_bytes(256) {
            let len = bytes.len().min(256);
            e[..len].copy_from_slice(&bytes[..len]);
        }
    }

    e[0..8].iter_mut().zip(ctr.to_le_bytes()).for_each(|(a, b)| *a ^= b);

    let t1: u64;
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        t1 = (lo as u64) | ((hi as u64) << 32);
    }
    e[8..16].iter_mut().zip(t1.to_le_bytes()).for_each(|(a, b)| *a ^= b);

    let eptr = &e as *const _ as u64;
    e[16..24].iter_mut().zip(eptr.to_le_bytes()).for_each(|(a, b)| *a ^= b);

    let gctr = rng::GLOBAL_COUNTER.fetch_add(0x0100_0000_0000_0001, AO::SeqCst);
    e[24..32].iter_mut().zip(gctr.to_le_bytes()).for_each(|(a, b)| *a ^= b);

    for i in 0..32 {
        unsafe {
            core::arch::asm!("out dx, al", in("dx") 0x43u16, in("al") 0x00u8, options(nostack, preserves_flags));
            let lo: u8;
            core::arch::asm!("in al, dx", out("al") lo, in("dx") 0x40u16, options(nostack, preserves_flags));
            let hi: u8;
            core::arch::asm!("in al, dx", out("al") hi, in("dx") 0x40u16, options(nostack, preserves_flags));
            e[32 + i * 2] ^= lo;
            e[33 + i * 2] ^= hi;
        }
        let spin = ((e[32 + i * 2] as usize) & 0x3F) + 1;
        for _ in 0..spin {
            core::hint::spin_loop();
        }
    }

    let t2: u64;
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        t2 = (lo as u64) | ((hi as u64) << 32);
    }
    e[96..104].iter_mut().zip(t2.to_le_bytes()).for_each(|(a, b)| *a ^= b);
    e[104..112].iter_mut().zip(t2.wrapping_sub(t1).to_le_bytes()).for_each(|(a, b)| *a ^= b);

    unsafe {
        core::arch::asm!("out dx, al", in("dx") 0x70u16, in("al") 0x00u8, options(nostack, preserves_flags));
        let sec: u8;
        core::arch::asm!("in al, dx", out("al") sec, in("dx") 0x71u16, options(nostack, preserves_flags));
        core::arch::asm!("out dx, al", in("dx") 0x70u16, in("al") 0x02u8, options(nostack, preserves_flags));
        let min: u8;
        core::arch::asm!("in al, dx", out("al") min, in("dx") 0x71u16, options(nostack, preserves_flags));
        core::arch::asm!("out dx, al", in("dx") 0x70u16, in("al") 0x04u8, options(nostack, preserves_flags));
        let hour: u8;
        core::arch::asm!("in al, dx", out("al") hour, in("dx") 0x71u16, options(nostack, preserves_flags));
        e[112] ^= sec;
        e[113] ^= min;
        e[114] ^= hour;
    }

    let sp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack));
    }
    e[120..128].iter_mut().zip(sp.to_le_bytes()).for_each(|(a, b)| *a ^= b);

    rng::fill_random_bytes(&mut e[128..192]);

    let t3: u64;
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        t3 = (lo as u64) | ((hi as u64) << 32);
    }
    e[192..200].iter_mut().zip(t3.to_le_bytes()).for_each(|(a, b)| *a ^= b);
    e[200..208].iter_mut().zip(t3.wrapping_sub(t2).to_le_bytes()).for_each(|(a, b)| *a ^= b);

    let ctr2 = WALLET_CTR.load(AO::SeqCst);
    e[208..216].iter_mut().zip(ctr2.to_le_bytes()).for_each(|(a, b)| *a ^= b);

    rng::fill_random_bytes(&mut e[216..256]);

    let master_key = blake3_hash(&e);

    for b in e.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }

    match init_wallet(master_key) {
        Ok(()) => {
            let mut pwd = PASSWORD_INPUT.lock();
            for b in pwd.iter_mut() { *b = 0; }
            PASSWORD_LEN.store(0, Ordering::SeqCst);
            PASSWORD_FOCUSED.store(false, Ordering::SeqCst);
            set_status(b"New wallet created", true);
        }
        Err(e) => {
            set_status(e.as_bytes(), false);
        }
    }
}

pub(super) fn try_unlock() {
    use crate::crypto::blake3_hash;

    let pwd = PASSWORD_INPUT.lock();
    let pwd_len = PASSWORD_LEN.load(Ordering::SeqCst);

    if pwd_len == 0 {
        set_status(b"Enter a master key", false);
        return;
    }

    let master_key = blake3_hash(&pwd[..pwd_len]);
    drop(pwd);

    match init_wallet(master_key) {
        Ok(()) => {
            let mut pwd = PASSWORD_INPUT.lock();
            for b in pwd.iter_mut() { *b = 0; }
            PASSWORD_LEN.store(0, Ordering::SeqCst);
            PASSWORD_FOCUSED.store(false, Ordering::SeqCst);
        }
        Err(e) => {
            set_status(e.as_bytes(), false);
        }
    }
}
