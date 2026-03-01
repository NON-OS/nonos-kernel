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

use super::scan_stats::sensitivity_to_value;
use super::types::SensitivityLevel;

#[test]
fn test_sensitivity_ordering() {
    assert!(sensitivity_to_value(SensitivityLevel::Critical) > sensitivity_to_value(SensitivityLevel::High));
    assert!(sensitivity_to_value(SensitivityLevel::High) > sensitivity_to_value(SensitivityLevel::Medium));
    assert!(sensitivity_to_value(SensitivityLevel::Medium) > sensitivity_to_value(SensitivityLevel::Low));
    assert!(sensitivity_to_value(SensitivityLevel::Low) > sensitivity_to_value(SensitivityLevel::None));
}
