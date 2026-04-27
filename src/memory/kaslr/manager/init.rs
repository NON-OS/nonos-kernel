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

use super::super::constants::NONCE_GEN_MULTIPLIER;
use super::super::constants::NONCE_ROTATE_BITS;
use super::super::error::{KaslrError, KaslrResult};
use super::super::types::{Kaslr, Policy};
use super::entropy::{collect_entropy, secure_hash};
use super::slide::choose_slide;
use super::state::{BOOT_NONCE, KASLR_SLIDE};
use crate::memory::layout;

pub fn init(policy: Policy) -> KaslrResult<Kaslr> {
    let entropy = collect_entropy();
    let slide = choose_slide(entropy, policy)?;

    let nonce = entropy.wrapping_mul(NONCE_GEN_MULTIPLIER).rotate_left(NONCE_ROTATE_BITS);
    BOOT_NONCE.store(nonce, Ordering::SeqCst);
    KASLR_SLIDE.store(slide, Ordering::SeqCst);

    layout::apply_kaslr_slide(slide).map_err(|_| KaslrError::LayoutApplyFailed)?;

    let entropy_bytes = entropy.to_le_bytes();
    let entropy_hash = secure_hash(&entropy_bytes);

    Ok(Kaslr { slide, entropy_hash, boot_nonce: nonce })
}

#[inline]
pub fn boot_nonce() -> KaslrResult<u64> {
    let nonce = BOOT_NONCE.load(Ordering::Relaxed);
    if nonce == 0 {
        Err(KaslrError::NotInitialized)
    } else {
        Ok(nonce)
    }
}

#[inline]
pub fn get_slide() -> u64 {
    KASLR_SLIDE.load(Ordering::Relaxed)
}

pub fn is_initialized() -> bool {
    BOOT_NONCE.load(Ordering::Relaxed) != 0
}
