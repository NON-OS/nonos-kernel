// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

mod api;
pub mod constants;
pub mod cpu_ops;
pub mod entry;
pub mod error;
pub mod stage;
pub mod state;
pub mod types;
pub mod validation;

pub use api::{
    boot_error, boot_stage, boot_tsc, cpu_family, cpu_features, cpu_model, cpu_stepping,
    exception_count, increment_exception_count, is_boot_complete, kernel_stack, simd_support,
};
pub use constants::{KERNEL_CS, KERNEL_DS, TSS_SEL, USER_CS, USER_DS};
pub use error::BootError;
pub use stage::BootStage;
pub use state::{get_stats, is_complete};
pub use types::{BootStats, CpuFeatures, ExceptionContext, InterruptFrame, Tss};
pub use validation::{SimdLevel, SimdSupport};
