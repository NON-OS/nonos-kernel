mod gts_root_r1;
mod gts_root_r2;
mod gts_root_r3;
mod gts_root_r4;

use super::super::types::TrustedRootCa;

pub(super) static GOOGLE_ROOTS: &[TrustedRootCa] =
    &[gts_root_r1::ROOT, gts_root_r2::ROOT, gts_root_r3::ROOT, gts_root_r4::ROOT];
