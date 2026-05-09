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

#[cfg(feature = "mldsa2")]
pub const PARAM_NAME: &str = "ML-DSA-44";
#[cfg(any(feature = "mldsa3", all(not(feature = "mldsa2"), not(feature = "mldsa5"))))]
pub const PARAM_NAME: &str = "ML-DSA-65";
#[cfg(feature = "mldsa5")]
pub const PARAM_NAME: &str = "ML-DSA-87";

#[cfg(feature = "mldsa2")]
pub const PUBLICKEY_BYTES: usize = 1312;
#[cfg(feature = "mldsa2")]
pub const SECRETKEY_BYTES: usize = 2560;
#[cfg(feature = "mldsa2")]
pub const SIGNATURE_BYTES: usize = 2420;

#[cfg(any(feature = "mldsa3", all(not(feature = "mldsa2"), not(feature = "mldsa5"))))]
pub const PUBLICKEY_BYTES: usize = 1952;
#[cfg(any(feature = "mldsa3", all(not(feature = "mldsa2"), not(feature = "mldsa5"))))]
pub const SECRETKEY_BYTES: usize = 4032;
#[cfg(any(feature = "mldsa3", all(not(feature = "mldsa2"), not(feature = "mldsa5"))))]
pub const SIGNATURE_BYTES: usize = 3309;

#[cfg(feature = "mldsa5")]
pub const PUBLICKEY_BYTES: usize = 2592;
#[cfg(feature = "mldsa5")]
pub const SECRETKEY_BYTES: usize = 4896;
#[cfg(feature = "mldsa5")]
pub const SIGNATURE_BYTES: usize = 4627;
