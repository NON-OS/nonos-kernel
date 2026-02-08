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

use std::{fs, path::PathBuf};

use blake3;
use clap::Parser;

use ark_bls12_381::Bls12_381;
use ark_groth16::VerifyingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::io::Cursor;

const DS_PROGRAM_DEFAULT: &str = "NONOS:ZK:PROGRAM:v1";

#[derive(Debug, Parser)]
#[command(name = "zk-embed", version, about = "NONOS zk-embed - derive PROGRAM_HASH and emit Groth16 VK bytes")]
struct Args {
    #[arg(long, value_name = "STR", group = "pid")]
    program_id_str: Option<String>,

    #[arg(long, value_name = "HEX", group = "pid")]
    program_id_hex: Option<String>,

    #[arg(long, value_name = "PATH", group = "pid")]
    program_id_file: Option<PathBuf>,

    #[arg(long = "vk", value_name = "PATH")]
    vk_path: PathBuf,

    #[arg(long, value_name = "NAME", default_value = "PROGRAM")]
    const_prefix: String,

    #[arg(long, value_name = "STR", default_value = DS_PROGRAM_DEFAULT)]
    ds_program: String,

    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("[x] {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();

    let pid_bytes = load_program_id_bytes(&args)?;

    let program_hash = derive_program_hash(&args.ds_program, &pid_bytes);

    let vk_bytes = load_and_normalize_vk(&args.vk_path)?;

    let prefix = sanitize_ident(&args.const_prefix);
    let snippet = build_snippet(&prefix, &args.ds_program, &program_hash, &vk_bytes);

    if let Some(path) = &args.out {
        fs::write(path, snippet.as_bytes())
            .map_err(|e| format!("write {}: {}", path.display(), e))?;
    } else {
        print!("{snippet}");
    }

    Ok(())
}

fn load_program_id_bytes(args: &Args) -> Result<Vec<u8>, String> {
    match (&args.program_id_str, &args.program_id_hex, &args.program_id_file) {
        (Some(s), None, None) => Ok(s.as_bytes().to_vec()),
        (None, Some(h), None) => {
            let h = h.trim().trim_start_matches("0x").trim_start_matches("0X");
            hex::decode(h).map_err(|e| format!("program-id-hex: {e}"))
        }
        (None, None, Some(p)) => fs::read(p).map_err(|e| format!("read program-id-file {}: {e}", p.display())),
        _ => Err("provide exactly one of --program-id-str | --program-id-hex | --program-id-file".into()),
    }
}

fn derive_program_hash(ds_program: &str, program_id_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ds_program);
    hasher.update(program_id_bytes);
    *hasher.finalize().as_bytes()
}

fn load_and_normalize_vk(path: &PathBuf) -> Result<Vec<u8>, String> {
    let vk_raw = fs::read(path).map_err(|e| format!("read verifying key {}: {e}", path.display()))?;
    if vk_raw.is_empty() {
        return Err("verifying key file is empty".into());
    }

    let vk = VerifyingKey::<Bls12_381>::deserialize_with_mode(
        &mut Cursor::new(&vk_raw),
        Compress::Yes,
        Validate::Yes,
    )
    .or_else(|_| {
        VerifyingKey::<Bls12_381>::deserialize_with_mode(
            &mut Cursor::new(&vk_raw),
            Compress::No,
            Validate::Yes,
        )
    })
    .map_err(|_| "failed to deserialize verifying key (neither compressed nor uncompressed)".to_string())?;

    let mut out = Vec::new();
    vk.serialize_with_mode(&mut out, Compress::Yes)
        .map_err(|_| "failed to serialize VK in compressed canonical form".to_string())?;
    Ok(out)
}

fn sanitize_ident(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "PROGRAM".to_string()
    } else {
        out
    }
}

fn build_snippet(prefix: &str, ds: &str, program_hash: &[u8; 32], vk_bytes: &[u8]) -> String {
    let mut out = String::new();

    out.push_str("// --- paste into src/zk/zkverify.rs ---\n");
    out.push_str(&format!("// DS: {ds}\n\n"));

    out.push_str(&format!("pub const PROGRAM_HASH_{prefix}: [u8; 32] = [\n"));
    for (i, b) in program_hash.iter().enumerate() {
        if i % 16 == 0 {
            out.push_str("    ");
        }
        out.push_str(&format!("0x{b:02x}"));
        if i != 31 {
            out.push_str(", ");
        }
        if i % 16 == 15 {
            out.push('\n');
        }
    }
    out.push_str("];\n\n");

    out.push_str(&format!(
        "pub const VK_{prefix}_BLS12_381_GROTH16: &[u8] = &[\n"
    ));
    for (i, b) in vk_bytes.iter().enumerate() {
        if i % 16 == 0 {
            out.push_str("    ");
        }
        out.push_str(&format!("0x{b:02x}"));
        if i + 1 != vk_bytes.len() {
            out.push_str(", ");
        }
        if i % 16 == 15 {
            out.push('\n');
        }
    }
    out.push_str("];\n\n");

    out.push_str("#[cfg(feature = \"zk-groth16\")]\n");
    out.push_str("fn program_vk_lookup(program_hash: &[u8; 32]) -> Option<&'static [u8]> {\n");
    out.push_str(&format!(
        "    if ct_eq32(program_hash, &PROGRAM_HASH_{prefix}) {{\n"
    ));
    out.push_str(&format!(
        "        return Some(VK_{prefix}_BLS12_381_GROTH16);\n"
    ));
    out.push_str("    }\n");
    out.push_str("    None\n");
    out.push_str("}\n");

    out.push_str("\n// done.\n");
    out
}
