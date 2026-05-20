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

mod cert_reason;
mod error;
mod manifest_reason;
mod run;
#[cfg(any(
    feature = "nonos-keyring-smoketest",
    feature = "nonos-entropy-smoketest",
    feature = "nonos-crypto-hash-smoketest",
    feature = "nonos-driver-virtio-rng-smoketest",
    feature = "nonos-driver-virtio-blk-smoketest",
    feature = "nonos-driver-virtio-net-smoketest",
    feature = "nonos-driver-ps2-input-smoketest",
    feature = "nonos-driver-xhci-smoketest",
    feature = "nonos-vfs-smoketest",
    feature = "nonos-market-smoketest",
))]
mod smoketest;

pub(crate) use run::boot;
#[cfg(any(
    feature = "nonos-keyring-smoketest",
    feature = "nonos-entropy-smoketest",
    feature = "nonos-crypto-hash-smoketest",
    feature = "nonos-driver-virtio-rng-smoketest",
    feature = "nonos-driver-virtio-blk-smoketest",
    feature = "nonos-driver-virtio-net-smoketest",
    feature = "nonos-driver-ps2-input-smoketest",
    feature = "nonos-driver-xhci-smoketest",
    feature = "nonos-vfs-smoketest",
    feature = "nonos-market-smoketest",
))]
pub(crate) use smoketest::run_smoketest;
