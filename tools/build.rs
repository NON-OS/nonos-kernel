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

use std::env;
use std::path::PathBuf;

fn main() {
    let pqclean = PathBuf::from("../third_party/pqclean");
    let mldsa = pqclean.join("crypto_sign/ml-dsa-65/clean");
    let common = pqclean.join("common");
    if !mldsa.exists() {
        panic!(
            "ML-DSA-65 source missing at {}; the host capsule-sign build needs the kernel's pqclean tree",
            mldsa.display()
        );
    }

    let pattern = mldsa.join("*.c").to_string_lossy().to_string();
    let mut files: Vec<PathBuf> = glob::glob(&pattern)
        .expect("glob")
        .filter_map(Result::ok)
        .filter(|p| p.exists())
        .collect();
    let fips = common.join("fips202.c");
    if !fips.exists() {
        panic!("missing pqclean common/fips202.c at {}", fips.display());
    }
    files.push(fips);
    files.push(PathBuf::from("src/capsule_sign/algs/mldsa65/host_randombytes.c"));

    let mut build = cc::Build::new();
    build
        .files(&files)
        .include(&mldsa)
        .include(&common)
        .opt_level(2)
        .warnings(false)
        .define("MLDSA65", None);

    build.compile("pqclean_mldsa65_host");

    println!("cargo:rerun-if-changed=src/capsule_sign/algs/mldsa65/host_randombytes.c");
    println!("cargo:rerun-if-changed={}", mldsa.display());
    println!("cargo:rerun-if-changed={}", common.display());

    let _ = env::var("OUT_DIR");
}
