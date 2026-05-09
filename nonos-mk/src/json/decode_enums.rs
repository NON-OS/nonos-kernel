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

use nonos_marketplace_abi::{PriceKind, ValidationStatus};

pub(super) fn price_kind_str(kind: PriceKind) -> &'static str {
    match kind {
        PriceKind::Free => "free",
        PriceKind::OneTime => "one_time",
        PriceKind::Subscription => "subscription",
        PriceKind::UsageMetered => "usage_metered",
    }
}

pub(super) fn validation_status_str(s: ValidationStatus) -> &'static str {
    match s {
        ValidationStatus::Unknown => "unknown",
        ValidationStatus::Pending => "pending",
        ValidationStatus::Validated => "validated",
        ValidationStatus::Rejected => "rejected",
    }
}
