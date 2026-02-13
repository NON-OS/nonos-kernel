// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use uefi::prelude::*;
use uefi::table::boot::BootServices;

use crate::handoff::ZeroStateBootInfo;

use super::sources::{collect_hw_rng_bytes, rdtsc_serialized};
use super::types::{DS_ENTROPY_ACCUM, DS_ENTROPY_OUTPUT, HW_RNG_ITERATIONS, TSC_JITTER_ROUNDS};
use super::util::{is_weak_entropy, scrub};

#[cfg(feature = "efi-rng")]
use uefi::proto::rng::Rng;

pub fn collect_boot_entropy_64_with_st(st: &SystemTable<Boot>) -> Result<[u8; 64], &'static str> {
    let bt = st.boot_services();
    let entropy = collect_boot_entropy(bt)?;
    Ok(entropy)
}

pub fn get_rtc_timestamp_with_st(st: &SystemTable<Boot>) -> [u8; 8] {
    if let Ok(rtc) = st.runtime_services().get_time() {
        let mut buf = [0u8; 8];
        let year: u16 = rtc.year();
        buf[0..2].copy_from_slice(&year.to_le_bytes());
        buf[2] = rtc.month();
        buf[3] = rtc.day();
        buf[4] = rtc.hour();
        buf[5] = rtc.minute();
        buf[6] = rtc.second();
        buf[7] = (rtc.nanosecond() / 1_000_000) as u8; // milliseconds
        buf
    } else {
        let tsc = rdtsc_serialized();
        tsc.to_le_bytes()
    }
}

pub fn collect_boot_entropy(bs: &BootServices) -> Result<[u8; 64], &'static str> {
    let mut h = blake3::Hasher::new_derive_key(DS_ENTROPY_ACCUM);

    #[cfg(feature = "efi-rng")]
    collect_efi_rng(bs, &mut h);

    let mut hw = [0u8; 64];
    collect_hw_rng_bytes(&mut hw, HW_RNG_ITERATIONS);
    h.update(&hw);
    scrub(&mut hw);

    collect_tsc_jitter(bs, &mut h);

    collect_rtc_entropy(&mut h);

    let mut out = [0u8; 64];
    blake3::Hasher::new_derive_key(DS_ENTROPY_OUTPUT)
        .update(h.finalize().as_bytes())
        .finalize_xof()
        .fill(&mut out);

    if is_weak_entropy(&out) {
        return Err("Entropy collection failed: insufficient randomness");
    }

    Ok(out)
}

#[cfg(feature = "efi-rng")]
fn collect_efi_rng(bs: &BootServices, h: &mut blake3::Hasher) {
    if let Ok(handle) = bs.locate_protocol::<Rng>() {
        // ## SAFETY: UEFI protocol obtained from BootServices
        let rng = unsafe { &mut *handle.get() };
        let mut buf = [0u8; 64];
        if rng.get_rng(None, &mut buf).is_ok() {
            h.update(&buf);
            scrub(&mut buf);
        }
    }
}

fn collect_tsc_jitter(bs: &BootServices, h: &mut blake3::Hasher) {
    for round in 0..TSC_JITTER_ROUNDS {
        let t1 = rdtsc_serialized();
        bs.stall(23 + ((round as usize * 7) % 17));
        let t2 = rdtsc_serialized();
        let delta = t2.wrapping_sub(t1);
        let mut frame = [0u8; 24];
        frame[0..8].copy_from_slice(&t1.to_le_bytes());
        frame[8..16].copy_from_slice(&t2.to_le_bytes());
        frame[16..20].copy_from_slice(&round.to_le_bytes());
        frame[20..24].copy_from_slice(&(delta.rotate_left((round % 63) + 1)).to_le_bytes()[0..4]);
        h.update(&frame);
    }
}

fn collect_rtc_entropy(h: &mut blake3::Hasher) {
    let tsc = rdtsc_serialized();
    h.update(&tsc.to_le_bytes());
}

pub fn seed_entropy(info: &mut ZeroStateBootInfo, bs: &BootServices) -> Result<(), &'static str> {
    let mut collected = collect_boot_entropy(bs)?;
    info.entropy64.copy_from_slice(&collected);
    scrub(&mut collected);
    Ok(())
}
