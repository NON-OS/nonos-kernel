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
pub const D_PARAM_NAME: &str = "ML-DSA-44 (Dilithium2)";
#[cfg(feature = "mldsa3")]
pub const D_PARAM_NAME: &str = "ML-DSA-65 (Dilithium3)";
#[cfg(feature = "mldsa5")]
pub const D_PARAM_NAME: &str = "ML-DSA-87 (Dilithium5)";

#[cfg(feature = "mldsa2")]
pub const PUBLICKEY_BYTES: usize = 1312;
#[cfg(feature = "mldsa2")]
pub const SECRETKEY_BYTES: usize = 2528;
#[cfg(feature = "mldsa2")]
pub const SIGNATURE_BYTES: usize = 2420;

#[cfg(feature = "mldsa3")]
pub const PUBLICKEY_BYTES: usize = 1952;
#[cfg(feature = "mldsa3")]
pub const SECRETKEY_BYTES: usize = 4000;
#[cfg(feature = "mldsa3")]
pub const SIGNATURE_BYTES: usize = 3293;

#[cfg(feature = "mldsa5")]
pub const PUBLICKEY_BYTES: usize = 2592;
#[cfg(feature = "mldsa5")]
pub const SECRETKEY_BYTES: usize = 4864;
#[cfg(feature = "mldsa5")]
pub const SIGNATURE_BYTES: usize = 4595;
