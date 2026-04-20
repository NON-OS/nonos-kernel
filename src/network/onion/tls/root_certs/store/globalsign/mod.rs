mod globalsign_root_e46;
mod globalsign_root_r46;

use super::super::types::TrustedRootCa;

pub static GLOBALSIGN_ROOTS: &[TrustedRootCa] = &[
    globalsign_root_e46::ROOT,
    globalsign_root_r46::ROOT,
];
