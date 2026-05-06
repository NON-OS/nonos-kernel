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

use super::writer::Writer;
use crate::types::ValidationReport;

pub(super) fn write(w: &mut Writer<'_>, report: &ValidationReport) {
    w.u8(report.status as u8);
    w.lp_string(&report.note);
    w.lp_string(&report.validator_id);
    w.u64(report.validated_at_ms);
}
