mod global;
mod global_g2;
mod global_g3;
mod high_assurance_ev;

use super::super::types::TrustedRootCa;

pub static DIGICERT_ROOTS: &[TrustedRootCa] = &[
    global::ROOT,
    global_g2::ROOT,
    global_g3::ROOT,
    high_assurance_ev::ROOT,
];
