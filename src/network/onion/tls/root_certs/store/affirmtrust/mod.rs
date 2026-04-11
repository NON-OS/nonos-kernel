mod affirmtrust_commercial;
mod affirmtrust_networking;
mod affirmtrust_premium;
mod affirmtrust_premium_ecc;

use super::super::types::TrustedRootCa;

pub static AFFIRMTRUST_ROOTS: &[TrustedRootCa] = &[
    affirmtrust_commercial::ROOT,
    affirmtrust_networking::ROOT,
    affirmtrust_premium::ROOT,
    affirmtrust_premium_ecc::ROOT,
];
