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

use nonos_marketplace_abi::{PriceKind, PriceModel};

use crate::error::CliError;

use super::schema::PriceJson;

pub(super) fn to_price(p: &PriceJson) -> Result<PriceModel, CliError> {
    let kind = match p.kind.as_str() {
        "free" => PriceKind::Free,
        "one_time" => PriceKind::OneTime,
        "subscription" => PriceKind::Subscription,
        "usage_metered" => PriceKind::UsageMetered,
        other => {
            return Err(CliError::UnknownEnum { field: "price.kind", value: other.to_string() })
        }
    };
    let amount_atomic = p
        .amount_atomic
        .parse::<u128>()
        .map_err(|_| CliError::Json(format!("price.amount_atomic: not a u128: {}", p.amount_atomic)))?;
    Ok(PriceModel { kind, amount_atomic, period_seconds: p.period_seconds })
}
