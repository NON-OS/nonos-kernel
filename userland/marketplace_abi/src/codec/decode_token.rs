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

use super::error::DecodeError;
use super::reader::Reader;
use super::strings::{bounded_bytes, bounded_string};
use crate::limits::MAX_TOKEN_SYMBOL;
use crate::types::TokenInfo;

const MAX_CONTRACT_LEN: u32 = 64;

pub(super) fn read(r: &mut Reader<'_>) -> Result<TokenInfo, DecodeError> {
    let symbol = bounded_string(r, MAX_TOKEN_SYMBOL)?;
    let decimals = r.u8()?;
    let chain_id = r.u64()?;
    let contract_address = bounded_bytes(r, MAX_CONTRACT_LEN)?;
    Ok(TokenInfo { symbol, decimals, chain_id, contract_address })
}
