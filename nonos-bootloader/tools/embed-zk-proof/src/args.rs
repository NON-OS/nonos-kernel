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

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "embed-zk-proof",
    about = "Generate and embed Groth16 ZK attestation into signed NONOS kernel"
)]
pub struct Args {
    #[arg(short, long, value_name = "FILE")]
    pub input: PathBuf,

    #[arg(short, long, value_name = "FILE")]
    pub output: PathBuf,

    #[arg(short = 'k', long, value_name = "FILE")]
    pub proving_key: PathBuf,

    #[arg(long, default_value = "nonos-production-attestation")]
    pub seed: String,

    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    pub verbose: bool,
}
