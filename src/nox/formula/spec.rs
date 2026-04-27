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

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub struct Formula {
    pub name: String,
    pub version: String,
    pub revision: u32,
    pub desc: String,
    pub homepage: String,
    pub license: String,
    pub url: String,
    pub sha256: String,
    pub mirror: Option<String>,
    pub bottle: Option<Bottle>,
    pub dependencies: Vec<Dependency>,
    pub build_dependencies: Vec<Dependency>,
    pub optional_dependencies: Vec<Dependency>,
    pub conflicts: Vec<String>,
    pub resources: Vec<Resource>,
    pub patches: Vec<Patch>,
    pub caveats: Option<String>,
    pub keg_only: bool,
    pub head: Option<String>,
    pub deprecated: bool,
    pub deprecation_reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FormulaSpec {
    pub name: String,
    pub tap: Option<String>,
    pub version: Option<String>,
}

impl FormulaSpec {
    pub fn parse(spec: &str) -> Self {
        let mut tap = None;
        let mut version = None;
        let name;
        if let Some(idx) = spec.find('@') {
            name = String::from(&spec[..idx]);
            version = Some(String::from(&spec[idx + 1..]));
        } else if let Some(_idx) = spec.find('/') {
            let parts: Vec<&str> = spec.splitn(3, '/').collect();
            if parts.len() >= 2 {
                tap = Some(alloc::format!("{}/{}", parts[0], parts[1]));
                name =
                    if parts.len() == 3 { String::from(parts[2]) } else { String::from(parts[1]) };
            } else {
                name = String::from(spec);
            }
        } else {
            name = String::from(spec);
        }
        Self { name, tap, version }
    }

    pub fn full_name(&self) -> String {
        match (&self.tap, &self.version) {
            (Some(t), Some(v)) => alloc::format!("{}/{}@{}", t, self.name, v),
            (Some(t), None) => alloc::format!("{}/{}", t, self.name),
            (None, Some(v)) => alloc::format!("{}@{}", self.name, v),
            (None, None) => self.name.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Bottle {
    pub root_url: String,
    pub sha256: Vec<(String, String)>,
    pub rebuild: u32,
}

#[derive(Clone, Debug)]
pub struct Resource {
    pub name: String,
    pub url: String,
    pub sha256: String,
}

#[derive(Clone, Debug)]
pub struct Patch {
    pub url: Option<String>,
    pub sha256: Option<String>,
    pub data: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Dependency {
    pub name: String,
    pub tap: Option<String>,
    pub version: Option<String>,
    pub optional: bool,
    pub build_time: bool,
    pub test_time: bool,
}

impl Formula {
    pub fn full_name(&self) -> String {
        alloc::format!("{}@{}", self.name, self.version)
    }
    pub fn versioned_name(&self) -> String {
        if self.revision > 0 {
            alloc::format!("{}-{}_r{}", self.name, self.version, self.revision)
        } else {
            alloc::format!("{}-{}", self.name, self.version)
        }
    }
}
