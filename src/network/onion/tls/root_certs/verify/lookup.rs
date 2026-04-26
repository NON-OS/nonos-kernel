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

pub(super) struct RootLookupStats {
    pub(super) exact_subject: usize,
    pub(super) same_len_subject: usize,
    pub(super) ski: usize,
}

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

pub(super) fn root_lookup_stats(issuer_der: &[u8], aki_value: Option<&[u8]>) -> RootLookupStats {
    let mut exact_subject = 0;
    let mut same_len_subject = 0;
    let mut ski_matches = 0;
    for group in TRUSTED_ROOT_GROUPS {
        for root in *group {
            if !root.subject_der.is_empty() && root.subject_der == issuer_der {
                exact_subject += 1;
            } else if !root.subject_der.is_empty() && root.subject_der.len() == issuer_der.len() {
                same_len_subject += 1;
            }
            if let (Some(root_ski), Some(aki)) = (root.ski, aki_value) {
                if root_ski == aki {
                    ski_matches += 1;
                }
            }
        }
    }
    RootLookupStats {
        exact_subject,
        same_len_subject,
        ski: ski_matches,
    }
}
