mod buypass_class_2_root_ca;
mod buypass_class_3_root_ca;

use super::super::types::TrustedRootCa;

pub(super) static BUYPASS_ROOTS: &[TrustedRootCa] = &[
    buypass_class_2_root_ca::ROOT,
    buypass_class_3_root_ca::ROOT,
];
