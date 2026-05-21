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

pub(super) fn run_all() {
    keyring();
    entropy();
    crypto();
}

#[cfg(feature = "nonos-keyring-smoketest")]
fn keyring() {
    super::super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_KEYRING,
        crate::security::keyring_capsule::smoketest::run,
    );
}
#[cfg(not(feature = "nonos-keyring-smoketest"))]
fn keyring() {}

#[cfg(feature = "nonos-entropy-smoketest")]
fn entropy() {
    super::super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_ENTROPY,
        crate::security::entropy_capsule::smoketest::run,
    );
}
#[cfg(not(feature = "nonos-entropy-smoketest"))]
fn entropy() {}

#[cfg(feature = "nonos-crypto-hash-smoketest")]
fn crypto() {
    super::super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_CRYPTO,
        crate::security::crypto_capsule::smoketest::run,
    );
}
#[cfg(not(feature = "nonos-crypto-hash-smoketest"))]
fn crypto() {}
