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

use nonos_marketplace_abi::TokenInfo;

use crate::error::CliError;

use super::schema::TokenJson;

pub(super) fn to_token(t: &TokenJson) -> Result<TokenInfo, CliError> {
    let contract_address = if t.contract_address.is_empty() {
        Vec::new()
    } else {
        let stripped = t.contract_address.trim_start_matches("0x");
        hex::decode(stripped)
            .map_err(|e| CliError::Json(format!("token.contract_address: {e}")))?
    };
    Ok(TokenInfo {
        symbol: t.symbol.clone(),
        decimals: t.decimals,
        chain_id: t.chain_id,
        contract_address,
    })
}
