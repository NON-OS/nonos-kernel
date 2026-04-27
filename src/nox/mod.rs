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

#![allow(dead_code)]

extern crate alloc;

pub mod commands;
pub mod config;
pub mod doctor;
pub mod error;
pub mod formula;
pub mod github;
pub mod output;
pub mod tap;

mod global;

pub use config::NoxConfig;
pub use doctor::DoctorCheck;
pub use error::NoxError;
pub use formula::{Formula, FormulaSpec};
pub use github::GitHubSource;
pub use output::Output;
pub use tap::{Tap, TapRegistry};

pub const NOX_VERSION: &str = "1.0.0";
pub const NOX_PREFIX: &str = "/nox";
pub const NOX_CELLAR: &str = "/nox/Cellar";
pub const NOX_CASKROOM: &str = "/nox/Caskroom";
pub const NOX_TAPS: &str = "/nox/Library/Taps";
pub const NOX_FORMULAS: &str = "/nox/Library/Formula";
pub const NOX_CACHE: &str = "/nox/Cache";
pub const NOX_LOGS: &str = "/nox/Logs";

pub type NoxResult<T> = Result<T, NoxError>;
