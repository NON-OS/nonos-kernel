mod identrust_commercial_root_ca_1;
mod identrust_public_sector_root_ca_1;

use super::super::types::TrustedRootCa;

pub(super) static IDENTRUST_ROOTS: &[TrustedRootCa] = &[
    identrust_commercial_root_ca_1::ROOT,
    identrust_public_sector_root_ca_1::ROOT,
];
