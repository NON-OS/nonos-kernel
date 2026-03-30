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

use alloc::collections::BTreeMap;
use alloc::string::String;

pub struct ScriptEnv {
    pub variables: BTreeMap<String, String>,
}

impl ScriptEnv {
    pub fn new(package: &str) -> Self {
        let mut variables = BTreeMap::new();
        variables.insert(String::from("PKG_NAME"), String::from(package));
        variables.insert(String::from("PKG_ROOT"), String::from("/"));
        Self { variables }
    }

    pub fn expand_variables(&self, s: &str) -> String {
        let mut result = String::from(s);
        for (key, value) in &self.variables {
            let pattern = alloc::format!("${{{}}}", key);
            result = result.replace(&pattern, value);
            let pattern2 = alloc::format!("${}", key);
            result = result.replace(&pattern2, value);
        }
        result
    }
}
