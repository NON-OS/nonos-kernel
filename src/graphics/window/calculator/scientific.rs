// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::sync::atomic::{AtomicBool, Ordering};

pub static SCIENTIFIC_MODE: AtomicBool = AtomicBool::new(false);
pub static DEGREE_MODE: AtomicBool = AtomicBool::new(true);

pub fn is_scientific_mode() -> bool {
    SCIENTIFIC_MODE.load(Ordering::Relaxed)
}
pub fn toggle_scientific_mode() {
    SCIENTIFIC_MODE.fetch_xor(true, Ordering::Relaxed);
}
pub fn is_degree_mode() -> bool {
    DEGREE_MODE.load(Ordering::Relaxed)
}
pub fn toggle_degree_mode() {
    DEGREE_MODE.fetch_xor(true, Ordering::Relaxed);
}

pub fn sin(x: f64) -> f64 {
    let rad = if is_degree_mode() { x * core::f64::consts::PI / 180.0 } else { x };
    libm::sin(rad)
}

pub fn cos(x: f64) -> f64 {
    let rad = if is_degree_mode() { x * core::f64::consts::PI / 180.0 } else { x };
    libm::cos(rad)
}

pub fn tan(x: f64) -> f64 {
    let rad = if is_degree_mode() { x * core::f64::consts::PI / 180.0 } else { x };
    libm::tan(rad)
}

pub fn asin(x: f64) -> f64 {
    let result = libm::asin(x);
    if is_degree_mode() {
        result * 180.0 / core::f64::consts::PI
    } else {
        result
    }
}

pub fn acos(x: f64) -> f64 {
    let result = libm::acos(x);
    if is_degree_mode() {
        result * 180.0 / core::f64::consts::PI
    } else {
        result
    }
}

pub fn atan(x: f64) -> f64 {
    let result = libm::atan(x);
    if is_degree_mode() {
        result * 180.0 / core::f64::consts::PI
    } else {
        result
    }
}

pub fn sqrt(x: f64) -> f64 {
    libm::sqrt(x)
}
pub fn cbrt(x: f64) -> f64 {
    libm::cbrt(x)
}
pub fn log10(x: f64) -> f64 {
    libm::log10(x)
}
pub fn ln(x: f64) -> f64 {
    libm::log(x)
}
pub fn log2(x: f64) -> f64 {
    libm::log2(x)
}
pub fn exp(x: f64) -> f64 {
    libm::exp(x)
}
pub fn pow(base: f64, exp: f64) -> f64 {
    libm::pow(base, exp)
}
pub fn factorial(n: u64) -> u64 {
    if n <= 1 {
        1
    } else {
        n * factorial(n - 1)
    }
}
pub fn abs(x: f64) -> f64 {
    libm::fabs(x)
}
pub fn floor(x: f64) -> f64 {
    libm::floor(x)
}
pub fn ceil(x: f64) -> f64 {
    libm::ceil(x)
}
pub fn round(x: f64) -> f64 {
    libm::round(x)
}

pub const PI: f64 = core::f64::consts::PI;
pub const E: f64 = core::f64::consts::E;
