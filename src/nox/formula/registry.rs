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

use super::spec::Formula;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub struct FormulaRegistry {
    formulas: BTreeMap<String, Formula>,
    installed: BTreeMap<String, InstalledFormula>,
}

#[derive(Clone, Debug)]
pub struct InstalledFormula {
    pub formula: Formula,
    pub install_time: u64,
    pub install_path: String,
    pub linked: bool,
    pub pinned: bool,
    pub installed_as_dependency: bool,
}

impl FormulaRegistry {
    pub fn new() -> Self {
        Self { formulas: BTreeMap::new(), installed: BTreeMap::new() }
    }

    pub fn register(&mut self, formula: Formula) {
        self.formulas.insert(formula.name.clone(), formula);
    }

    pub fn get(&self, name: &str) -> Option<&Formula> {
        self.formulas.get(name)
    }

    pub fn search(&self, query: &str) -> Vec<&Formula> {
        let q = query.to_lowercase();
        self.formulas
            .values()
            .filter(|f| f.name.to_lowercase().contains(&q) || f.desc.to_lowercase().contains(&q))
            .collect()
    }

    pub fn mark_installed(&mut self, formula: Formula, path: String, as_dep: bool) {
        let name = formula.name.clone();
        self.installed.insert(
            name,
            InstalledFormula {
                formula,
                install_time: 0,
                install_path: path,
                linked: true,
                pinned: false,
                installed_as_dependency: as_dep,
            },
        );
    }

    pub fn mark_removed(&mut self, name: &str) -> Option<InstalledFormula> {
        self.installed.remove(name)
    }

    pub fn is_installed(&self, name: &str) -> bool {
        self.installed.contains_key(name)
    }

    pub fn get_installed(&self, name: &str) -> Option<&InstalledFormula> {
        self.installed.get(name)
    }

    pub fn list_installed(&self) -> Vec<&InstalledFormula> {
        self.installed.values().collect()
    }

    pub fn list_leaves(&self) -> Vec<&InstalledFormula> {
        self.installed.values().filter(|f| !f.installed_as_dependency).collect()
    }

    pub fn list_all(&self) -> Vec<&Formula> {
        self.formulas.values().collect()
    }

    pub fn outdated(&self) -> Vec<(&InstalledFormula, &Formula)> {
        self.installed
            .iter()
            .filter_map(|(name, inst)| {
                self.formulas.get(name).and_then(|latest| {
                    if latest.version != inst.formula.version {
                        Some((inst, latest))
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    pub fn count(&self) -> usize {
        self.formulas.len()
    }
    pub fn installed_count(&self) -> usize {
        self.installed.len()
    }
}

impl Default for FormulaRegistry {
    fn default() -> Self {
        Self::new()
    }
}
