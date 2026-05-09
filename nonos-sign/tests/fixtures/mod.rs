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

mod bundle;
mod cert_input;
mod cert_sign;
mod consts;
mod manifest_input;
mod manifest_sign;
mod policy;

pub use bundle::make_bundle;
pub use cert_input::cert_input;
pub use cert_sign::{sign_cert, sign_cert_only_ed, sign_cert_with_corrupted_ed};
pub use consts::{CERT_SERIAL, NOW_MS, REQUIRED_ALGS, VALID_FROM, VALID_UNTIL};
pub use manifest_input::{cert_id_of, manifest_input};
pub use manifest_sign::{sign_manifest_corrupt_ed, sign_manifest_full, sign_manifest_only_ed};
pub use policy::{encode_policy, ta_policy};
