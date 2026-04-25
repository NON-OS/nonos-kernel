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

use super::spec::{Dependency, Formula};
use crate::nox::{NoxError, NoxResult};
use alloc::string::String;
use alloc::vec::Vec;

pub struct FormulaParser;

impl FormulaParser {
    pub fn parse(content: &str) -> NoxResult<Formula> {
        let mut name = String::new();
        let mut version = String::new();
        let mut revision = 0u32;
        let mut desc = String::new();
        let mut homepage = String::new();
        let mut license = String::new();
        let mut url = String::new();
        let mut sha256 = String::new();
        let mut dependencies = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("name:") {
                name = Self::extract_value(line);
            } else if line.starts_with("version:") {
                version = Self::extract_value(line);
            } else if line.starts_with("revision:") {
                revision = Self::extract_value(line).parse().unwrap_or(0);
            } else if line.starts_with("desc:") {
                desc = Self::extract_value(line);
            } else if line.starts_with("homepage:") {
                homepage = Self::extract_value(line);
            } else if line.starts_with("license:") {
                license = Self::extract_value(line);
            } else if line.starts_with("url:") {
                url = Self::extract_value(line);
            } else if line.starts_with("sha256:") {
                sha256 = Self::extract_value(line);
            } else if line.starts_with("depends_on:") {
                let dep_name = Self::extract_value(line);
                dependencies.push(Dependency {
                    name: dep_name,
                    tap: None,
                    version: None,
                    optional: false,
                    build_time: false,
                    test_time: false,
                });
            }
        }

        if name.is_empty() {
            return Err(NoxError::InvalidFormula(String::from("missing name")));
        }
        if version.is_empty() {
            return Err(NoxError::InvalidFormula(String::from("missing version")));
        }

        Ok(Formula {
            name,
            version,
            revision,
            desc,
            homepage,
            license,
            url,
            sha256,
            mirror: None,
            bottle: None,
            dependencies,
            build_dependencies: Vec::new(),
            optional_dependencies: Vec::new(),
            conflicts: Vec::new(),
            resources: Vec::new(),
            patches: Vec::new(),
            caveats: None,
            keg_only: false,
            head: None,
            deprecated: false,
            deprecation_reason: None,
        })
    }

    fn extract_value(line: &str) -> String {
        if let Some(idx) = line.find(':') {
            let val = line[idx + 1..].trim();
            let val = val.trim_matches('"').trim_matches('\'');
            String::from(val)
        } else {
            String::new()
        }
    }
}
