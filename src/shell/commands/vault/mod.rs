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

mod state;
mod format;
mod status;
mod seal;
mod keys;
mod crypto;

pub use self::status::{cmd_vault_status, cmd_vault_policy, cmd_vault_audit};
pub use self::seal::{cmd_vault_seal, cmd_vault_unseal, cmd_vault_erase};
pub use self::keys::{cmd_vault_derive, cmd_vault_keys};
pub use self::crypto::{cmd_vault_sign, cmd_vault_verify, cmd_vault_encrypt, cmd_vault_decrypt};
