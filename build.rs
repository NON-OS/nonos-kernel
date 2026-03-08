// build.rs - NØNOS Kernel Build Script with Cryptographic Signing and PQClean (Kyber) integration

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=abi/manifest.toml");
    println!("cargo:rerun-if-changed=third_party/pqclean");
    println!("cargo:rerun-if-changed=src/crypto/pqclean_support/randombytes.c");

    // Compile PQClean ML-KEM (Kyber) if vendor is present
    compile_pqclean_kyber();

    // Kernel static link flags
    configure_kernel_target();

    // Generate manifest + signature and embed them into dedicated sections
    generate_manifest_and_signature();

    // Build metadata
    embed_kernel_build_info();
}

fn compile_pqclean_kyber() {
    // Skip PQClean compilation when building tests on host
    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("apple") || target.contains("linux-gnu") || target.contains("windows") {
        return;
    }

    // Select parameter set
    let (kem_dir, kem_macro) = if cfg!(feature = "mlkem1024") {
        ("mlkem1024", "MLKEM1024")
    } else if cfg!(feature = "mlkem512") {
        ("mlkem512", "MLKEM512")
    } else {
        ("mlkem768", "MLKEM768")
    };

    let base = PathBuf::from(format!("third_party/pqclean/crypto_kem/{}/clean", kem_dir));
    if !base.exists() {
        eprintln!(
            "warning: PQClean directory not found at {} — skipping Kyber C build",
            base.display()
        );
        return;
    }

    // Collect all clean C sources
    let pattern = base.join("*.c").to_string_lossy().to_string();
    let mut files: Vec<_> = glob::glob(&pattern)
        .expect("glob failed")
        .filter_map(Result::ok)
        .collect();

    // RNG glue for PQClean
    files.push(PathBuf::from("src/crypto/pqclean_support/randombytes.c"));

    let mut build = cc::Build::new();
    build
        .files(files)
        .include(&base)
        .include("src/crypto/pqclean_support")
        // Hardened flags suitable for constant-time C
        .flag_if_supported("-O2")
        .flag_if_supported("-fPIC")
        .flag_if_supported("-fno-builtin")
        .flag_if_supported("-fno-strict-aliasing")
        .flag_if_supported("-fwrapv")
        .flag_if_supported("-fno-omit-frame-pointer")
        .flag_if_supported("-fno-tree-vectorize")
        .flag_if_supported("-fno-tree-slp-vectorize")
        .define(kem_macro, None)
        .warnings(false);

    build.compile("pqclean_mlkem_clean");
}

fn configure_kernel_target() {
    // Skip kernel linker config when building tests on host
    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("apple") || target.contains("linux-gnu") || target.contains("windows") {
        // Running tests on host - don't use kernel linker script
        return;
    }

    // Linker script path (relative to CARGO_MANIFEST_DIR for portability)
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let linker_script = format!("{}/linker.ld", manifest_dir);
    println!("cargo:rustc-link-arg=--script={}", linker_script);

    // Static link for bare-metal kernel
    println!("cargo:rustc-link-arg=-nostdlib");
    println!("cargo:rustc-link-arg=-static");
    println!("cargo:rustc-link-arg=--gc-sections");
    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=max-page-size=0x1000");
}

fn generate_manifest_and_signature() {
    let out_dir = env::var("OUT_DIR").unwrap();

    // Generate manifest content
    let manifest_content = generate_manifest_content();
    let manifest_data_path = format!("{}/manifest.bin", out_dir);
    fs::write(&manifest_data_path, &manifest_content).expect("Failed to write manifest");

    // Production signing: Ed25519 via NONOS_SIGNING_KEY
    // - If PROFILE=release and key missing/invalid => fail build
    // - In dev, warn and embed a zeroed signature (for local bring-up only)
    let profile = env::var("PROFILE").unwrap_or_default();
    let sig = match env::var("NONOS_SIGNING_KEY") {
        Ok(p) => {
            let key_path = PathBuf::from(&p);
            if key_path.exists() {
                sign_manifest_ed25519(&manifest_content, key_path)
                    .expect("Ed25519 signing failed")
            } else if profile == "release" {
                panic!("NONOS_SIGNING_KEY file not found at {} (required for release builds)", p);
            } else {
                eprintln!("warning: NONOS_SIGNING_KEY file not found at {}; embedding zero signature (dev build only)", p);
                vec![0u8; 64]
            }
        }
        Err(_) if profile == "release" => {
            panic!("NONOS_SIGNING_KEY not set (required for release builds to produce a signed manifest)");
        }
        Err(_) => {
            eprintln!("warning: NONOS_SIGNING_KEY not set; embedding zero signature (dev build only)");
            vec![0u8; 64]
        }
    };

    let signature_data_path = format!("{}/signature.bin", out_dir);
    fs::write(&signature_data_path, &sig).expect("Failed to write signature");

    // Emit a C TU that embeds both blobs in dedicated sections and link it in
    generate_manifest_asm(&manifest_content, &sig, &out_dir);
}

fn generate_manifest_content() -> Vec<u8> {
    use std::collections::HashMap;

    let mut manifest = HashMap::new();

    // Module ID — Blake3("nonos_kernel")
    let module_id = blake3::hash(b"nonos_kernel").as_bytes().to_vec();
    manifest.insert("module_id".to_string(), module_id);

    // Entry symbol
    manifest.insert("entry_symbol".to_string(), b"_start".to_vec());

    // Required capabilities
    manifest.insert("required_caps".to_string(), b"memory,interrupts,syscalls".to_vec());

    // Minimum heap size (16MB)
    let heap_size: u64 = 16 * 1024 * 1024;
    manifest.insert("min_heap_bytes".to_string(), heap_size.to_le_bytes().to_vec());

    // Version
    let version: u32 = 1;
    manifest.insert("version".to_string(), version.to_le_bytes().to_vec());

    // Build epoch (ns)
    use std::time::{SystemTime, UNIX_EPOCH};
    let epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    manifest.insert("build_epoch_ns".to_string(), epoch.to_le_bytes().to_vec());

    serialize_manifest(manifest)
}

fn serialize_manifest(manifest: std::collections::HashMap<String, Vec<u8>>) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    for (key, value) in manifest {
        result.extend_from_slice(&(key.len() as u32).to_le_bytes());
        result.extend_from_slice(key.as_bytes());
        result.extend_from_slice(&(value.len() as u32).to_le_bytes());
        result.extend_from_slice(&value);
    }
    result
}

fn sign_manifest_ed25519(data: &[u8], key_path: PathBuf) -> Result<Vec<u8>, String> {
    use ed25519_dalek::{Keypair, SecretKey, Signature, Signer};
    use sha2::{Digest, Sha512};

    let key_bytes = fs::read(&key_path).map_err(|e| format!("read key: {e}"))?;
    let kp = if key_bytes.len() == 32 {
        // 32-byte seed (secret scalar)
        let sk = SecretKey::from_bytes(&key_bytes).map_err(|e| format!("secret key: {e}"))?;
        let pk = ed25519_dalek::PublicKey::from(&sk);
        Keypair { secret: sk, public: pk }
    } else if key_bytes.len() == 64 {
        Keypair::from_bytes(&key_bytes).map_err(|e| format!("keypair: {e}"))?
    } else {
        return Err("NONOS_SIGNING_KEY must be 32-byte seed or 64-byte keypair".into());
    };

    // Contextualize via SHA-512(domain||manifest)
    let mut h = Sha512::new();
    h.update(b"NONOS_CAPSULE_V1");
    h.update(data);
    let digest = h.finalize();

    let sig: Signature = kp.sign(&digest);
    Ok(sig.to_bytes().to_vec())
}

fn embed_kernel_build_info() {
    let build_time = std::process::Command::new("date")
        .arg("+%Y-%m-%d %H:%M:%S UTC")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=NONOS_KERNEL_BUILD_TIME={}", build_time);

    if let Ok(output) = std::process::Command::new("git").args(["rev-parse", "--short", "HEAD"]).output() {
        let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("cargo:rustc-env=NONOS_KERNEL_GIT_COMMIT={}", commit);
    } else {
        println!("cargo:rustc-env=NONOS_KERNEL_GIT_COMMIT=unknown");
    }

    println!("cargo:rustc-env=NONOS_KERNEL_NAME=NØN-OS Kernel");
    println!("cargo:rustc-env=NONOS_KERNEL_VERSION=0.1.0");
}

fn generate_manifest_asm(manifest_content: &[u8], signature: &[u8], out_dir: &str) {
    // Generate assembly file directly - this works better for cross-compilation
    // than C because we don't need a cross-compiler toolchain
    let manifest_hex: String = manifest_content.iter().map(|b| format!("0x{:02x}, ", b)).collect();
    let signature_hex: String = signature.iter().map(|b| format!("0x{:02x}, ", b)).collect();

    let asm_content = format!(
        r#".section .nonos.manifest, "a", @progbits
.global __nonos_manifest_data
.global __nonos_manifest_size
__nonos_manifest_data:
    .byte {manifest_hex}
__nonos_manifest_size:
    .quad {manifest_len}

.section .nonos.sig, "a", @progbits
.global __nonos_signature_data
.global __nonos_signature_size
__nonos_signature_data:
    .byte {signature_hex}
__nonos_signature_size:
    .quad {signature_len}
"#,
        manifest_hex = manifest_hex.trim_end_matches(", "),
        manifest_len = manifest_content.len(),
        signature_hex = signature_hex.trim_end_matches(", "),
        signature_len = signature.len()
    );

    let asm_path = format!("{}/manifest_data.s", out_dir);
    fs::write(&asm_path, &asm_content).expect("Failed to write manifest assembly");

    // Generate a Rust file using global_asm! to ensure the data is always linked
    let manifest_bytes: String = manifest_content.iter().map(|b| format!("0x{:02x}, ", b)).collect();
    let signature_bytes: String = signature.iter().map(|b| format!("0x{:02x}, ", b)).collect();

    let rs_content = format!(
        r#"// Auto-generated manifest and signature data
// DO NOT EDIT - generated by build.rs

/// Manifest length constant
pub const MANIFEST_LEN: usize = {manifest_len};

/// Signature length constant
pub const SIGNATURE_LEN: usize = {signature_len};

#[cfg(not(feature = "std"))]
mod _embed {{
    use core::arch::global_asm;

    // Embed manifest data using global assembly (survives all optimization)
    global_asm!(
        ".section .nonos.manifest, \"aw\", @progbits",
        ".global NONOS_MANIFEST_DATA",
        ".global NONOS_MANIFEST_LEN",
        "NONOS_MANIFEST_DATA:",
        ".byte {manifest_bytes}",
        "NONOS_MANIFEST_LEN:",
        ".quad {manifest_len}",
    );

    // Embed signature data using global assembly
    global_asm!(
        ".section .nonos.sig, \"aw\", @progbits",
        ".global NONOS_SIGNATURE_DATA",
        ".global NONOS_SIGNATURE_LEN",
        "NONOS_SIGNATURE_DATA:",
        ".byte {signature_bytes}",
        "NONOS_SIGNATURE_LEN:",
        ".quad {signature_len}",
    );
}}

#[cfg(not(feature = "std"))]
extern "C" {{
    /// Manifest data (defined in assembly)
    pub static NONOS_MANIFEST_DATA: [u8; {manifest_len}];
    /// Signature data (defined in assembly)
    pub static NONOS_SIGNATURE_DATA: [u8; {signature_len}];
}}

/// Get the kernel manifest
#[cfg(not(feature = "std"))]
pub fn get_manifest() -> &'static [u8] {{
    unsafe {{ &NONOS_MANIFEST_DATA }}
}}

/// Get the kernel signature
#[cfg(not(feature = "std"))]
pub fn get_signature() -> &'static [u8] {{
    unsafe {{ &NONOS_SIGNATURE_DATA }}
}}
"#,
        manifest_bytes = manifest_bytes.trim_end_matches(", "),
        manifest_len = manifest_content.len(),
        signature_bytes = signature_bytes.trim_end_matches(", "),
        signature_len = signature.len()
    );

    let rs_path = format!("{}/manifest_data.rs", out_dir);
    fs::write(&rs_path, &rs_content).expect("Failed to write manifest Rust module");

    // Output info for debugging
    eprintln!("info: Generated manifest ({} bytes) and signature ({} bytes)",
              manifest_content.len(), signature.len());
    eprintln!("info: Signature (first 16 bytes): {:02x?}", &signature[..16.min(signature.len())]);
}
