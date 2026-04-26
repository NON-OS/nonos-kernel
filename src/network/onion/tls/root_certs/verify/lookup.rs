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

use super::super::store::TRUSTED_ROOT_GROUPS;
use super::super::types::TrustedRootCa;
use crate::network::onion::nonos_crypto::dn_equal;
use alloc::vec::Vec;

pub fn trusted_root_count() -> usize {
    TRUSTED_ROOT_GROUPS.iter().map(|g| g.len()).sum()
}

pub fn find_roots_by_subject_dn(issuer_der: &[u8]) -> Vec<&'static TrustedRootCa> {
    let mut results = Vec::new();
    for group in TRUSTED_ROOT_GROUPS {
        for root in *group {
            if !root.subject_der.is_empty() && root.subject_der == issuer_der {
                results.push(root);
            }
        }
    }
    if !results.is_empty() { return results; }
    for group in TRUSTED_ROOT_GROUPS {
        for root in *group {
            if !root.subject_der.is_empty()
                && root.subject_der.len() == issuer_der.len()
                && dn_equal(root.subject_der, issuer_der) {
                    results.push(root);
                }
        }
    }
    results
}

pub fn find_roots_by_ski(aki_value: &[u8]) -> Vec<&'static TrustedRootCa> {
    let mut results = Vec::new();
    for group in TRUSTED_ROOT_GROUPS {
        for root in *group {
            if let Some(ski) = root.ski {
                if ski == aki_value { results.push(root); }
            }
        }
    }
    results
}
