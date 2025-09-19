// build.rs - NØN-OS Kernel Build Script with Cryptographic Signing
// Generates .nonos.manifest and .nonos.sig sections for secure boot

use std::env;
use std::fs;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=abi/manifest.toml");

    // Configure kernel target
    configure_kernel_target();
    
    // Generate manifest and signature data
    generate_manifest_and_signature();
    
    // Set up kernel-specific linker flags
    configure_kernel_linker();
    
    // Embed build information
    embed_kernel_build_info();
}

fn configure_kernel_target() {
    // Kernel-specific compilation flags
    println!("cargo:rustc-link-arg=-nostdlib");
    println!("cargo:rustc-link-arg=-static");
    println!("cargo:rustc-link-arg=--gc-sections");
    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=max-page-size=0x1000");
}

fn configure_kernel_linker() {
    // The manifest assembly object will be linked automatically by generate_manifest_asm
}

fn generate_manifest_and_signature() {
    let out_dir = env::var("OUT_DIR").unwrap();
    
    // Generate manifest content
    let manifest_content = generate_manifest_content();
    let manifest_data_path = format!("{}/manifest.bin", out_dir);
    fs::write(&manifest_data_path, &manifest_content).expect("Failed to write manifest");
    
    // Generate signature over manifest
    let signature = sign_manifest(&manifest_content);
    let signature_data_path = format!("{}/signature.bin", out_dir);
    fs::write(&signature_data_path, &signature).expect("Failed to write signature");
    
    // Generate inline assembly with the data embedded
    generate_manifest_asm(&manifest_content, &signature, &out_dir);
}

fn generate_manifest_content() -> Vec<u8> {
    use std::collections::HashMap;
    
    // Create manifest based on abi/manifest.toml structure
    let mut manifest = HashMap::new();
    
    // Module ID (32 bytes) - Blake3 hash of kernel name
    let module_id = blake3::hash(b"nonos_kernel").as_bytes().to_vec();
    manifest.insert("module_id".to_string(), module_id);
    
    // Entry symbol
    manifest.insert("entry_symbol".to_string(), b"_start".to_vec());
    
    // Required capabilities
    let caps = b"memory,interrupts,syscalls".to_vec();
    manifest.insert("required_caps".to_string(), caps);
    
    // Minimum heap size (16MB)
    let heap_size: u64 = 16 * 1024 * 1024;
    manifest.insert("min_heap_bytes".to_string(), heap_size.to_le_bytes().to_vec());
    
    // Version
    let version: u32 = 1;
    manifest.insert("version".to_string(), version.to_le_bytes().to_vec());
    
    // Build epoch (current timestamp)
    use std::time::{SystemTime, UNIX_EPOCH};
    let epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    manifest.insert("build_epoch_ns".to_string(), epoch.to_le_bytes().to_vec());
    
    // Serialize manifest to binary format
    serialize_manifest(manifest)
}

fn serialize_manifest(manifest: std::collections::HashMap<String, Vec<u8>>) -> Vec<u8> {
    let mut result = Vec::new();
    
    // Simple binary format: [field_count: u32] [field_name_len: u32] [field_name] [field_data_len: u32] [field_data] ...
    result.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    
    for (key, value) in manifest {
        result.extend_from_slice(&(key.len() as u32).to_le_bytes());
        result.extend_from_slice(key.as_bytes());
        result.extend_from_slice(&(value.len() as u32).to_le_bytes());
        result.extend_from_slice(&value);
    }
    
    result
}

fn sign_manifest(manifest_data: &[u8]) -> Vec<u8> {
    // For now, generate a mock signature using Blake3 hash
    // In production, this would use a proper Ed25519 private key
    let context = b"NONOS_CAPSULE_V1";
    let mut hasher = blake3::Hasher::new();
    hasher.update(context);
    hasher.update(manifest_data);
    let hash = hasher.finalize();
    
    // Return 64-byte signature (Ed25519 signature format)
    let mut signature = vec![0u8; 64];
    signature[..32].copy_from_slice(hash.as_bytes());
    // Second 32 bytes would be the signature part in real Ed25519
    signature[32..].copy_from_slice(hash.as_bytes());
    
    signature
}

#[allow(dead_code)]
fn create_manifest_object(data_path: &str, output_path: &str) {
    // Use objcopy to create an object file with the manifest data in .nonos.manifest section
    let status = Command::new("objcopy")
        .args([
            "--input-format", "binary",
            "--output-format", "elf64-x86-64",
            "--binary-architecture", "i386:x86-64",
            "--rename-section", ".data=.nonos.manifest,alloc,load,readonly",
            data_path,
            output_path
        ])
        .status();
        
    if !status.map(|s| s.success()).unwrap_or(false) {
        // Fallback: create a simple assembly file
        create_manifest_asm(data_path, output_path);
    }
}

#[allow(dead_code)]
fn create_signature_object(data_path: &str, output_path: &str) {
    // Use objcopy to create an object file with the signature data in .nonos.sig section
    let status = Command::new("objcopy")
        .args([
            "--input-format", "binary",
            "--output-format", "elf64-x86-64",
            "--binary-architecture", "i386:x86-64",
            "--rename-section", ".data=.nonos.sig,alloc,load,readonly",
            data_path,
            output_path
        ])
        .status();
        
    if !status.map(|s| s.success()).unwrap_or(false) {
        // Fallback: create a simple assembly file
        create_signature_asm(data_path, output_path);
    }
}

#[allow(dead_code)]
fn create_manifest_asm(data_path: &str, output_path: &str) {
    let data = fs::read(data_path).expect("Failed to read manifest data");
    let out_dir = env::var("OUT_DIR").unwrap();
    let asm_path = format!("{}/manifest.s", out_dir);
    
    let mut asm_content = String::from(".section .nonos.manifest,\"a\",@progbits\n");
    asm_content.push_str(".global __nonos_manifest_start\n");
    asm_content.push_str("__nonos_manifest_start:\n");
    
    for byte in data {
        asm_content.push_str(&format!(".byte 0x{:02x}\n", byte));
    }
    
    asm_content.push_str(".global __nonos_manifest_end\n");
    asm_content.push_str("__nonos_manifest_end:\n");
    
    fs::write(&asm_path, asm_content).expect("Failed to write manifest assembly");
    
    // Assemble
    Command::new("as")
        .args(["--64", "-o", output_path, &asm_path])
        .status()
        .expect("Failed to assemble manifest");
}

#[allow(dead_code)]
fn create_signature_asm(data_path: &str, output_path: &str) {
    let data = fs::read(data_path).expect("Failed to read signature data");
    let out_dir = env::var("OUT_DIR").unwrap();
    let asm_path = format!("{}/signature.s", out_dir);
    
    let mut asm_content = String::from(".section .nonos.sig,\"a\",@progbits\n");
    asm_content.push_str(".global __nonos_signature_start\n");
    asm_content.push_str("__nonos_signature_start:\n");
    
    for byte in data {
        asm_content.push_str(&format!(".byte 0x{:02x}\n", byte));
    }
    
    asm_content.push_str(".global __nonos_signature_end\n");
    asm_content.push_str("__nonos_signature_end:\n");
    
    fs::write(&asm_path, asm_content).expect("Failed to write signature assembly");
    
    // Assemble
    Command::new("as")
        .args(["--64", "-o", output_path, &asm_path])
        .status()
        .expect("Failed to assemble signature");
}

fn embed_kernel_build_info() {
    // Build timestamp
    let build_time = std::process::Command::new("date")
        .arg("+%Y-%m-%d %H:%M:%S UTC")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    
    println!("cargo:rustc-env=NONOS_KERNEL_BUILD_TIME={}", build_time);
    
    // Git commit if available
    if let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output() {
        let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("cargo:rustc-env=NONOS_KERNEL_GIT_COMMIT={}", commit);
    } else {
        println!("cargo:rustc-env=NONOS_KERNEL_GIT_COMMIT=unknown");
    }
    
    println!("cargo:rustc-env=NONOS_KERNEL_NAME=NØN-OS Kernel");
    println!("cargo:rustc-env=NONOS_KERNEL_VERSION=0.1.0");
}

fn generate_manifest_asm(manifest_content: &[u8], signature: &[u8], out_dir: &str) {
    // Instead of using cargo linker args, let's create a C file that gets compiled directly
    // Use exact symbols the kernel expects
    let c_content = format!(r#"
__attribute__((section(".nonos.manifest")))
const unsigned char __nonos_manifest_start[] = {{
    {}
}};

__attribute__((section(".nonos.manifest")))  
const unsigned char __nonos_manifest_end[] = {{ 0 }};

__attribute__((section(".nonos.sig")))
const unsigned char __nonos_signature_start[] = {{
    {}
}};

__attribute__((section(".nonos.sig")))
const unsigned char __nonos_signature_end[] = {{ 0 }};
"#,
        manifest_content.iter().map(|b| format!("0x{:02x}", b)).collect::<Vec<_>>().join(","),
        signature.iter().map(|b| format!("0x{:02x}", b)).collect::<Vec<_>>().join(",")
    );
    
    // Write the C file
    let c_path = format!("{}/manifest_data.c", out_dir);
    fs::write(&c_path, c_content).expect("Failed to write manifest C file");
    
    // Compile it into an object file using clang with the right target
    let object_path = format!("{}/manifest_data.o", out_dir);
    let status = Command::new("clang")
        .args([
            "-target", "x86_64-unknown-none",
            "-c", 
            "-o", &object_path,
            &c_path
        ])
        .status();
        
    match status {
        Ok(status) if status.success() => {
            // Create a static library from the object file
            let lib_path = format!("{}/libmanifest.a", out_dir);
            let ar_status = Command::new("ar")
                .args(["rcs", &lib_path, &object_path])
                .status()
                .expect("Failed to run ar");
                
            if ar_status.success() {
                // Link the static library
                println!("cargo:rustc-link-search=native={}", out_dir);
                println!("cargo:rustc-link-lib=static=manifest");
            } else {
                // Fallback to direct object linking
                println!("cargo:rustc-link-arg={}", object_path);
            }
        }
        _ => {
            // Fallback: try with gcc
            let status = Command::new("gcc")
                .args([
                    "-c",
                    "-o", &object_path, 
                    &c_path
                ])
                .status()
                .expect("Failed to run gcc");
                
            if status.success() {
                let lib_path = format!("{}/libmanifest.a", out_dir);
                let ar_status = Command::new("ar")
                    .args(["rcs", &lib_path, &object_path])
                    .status();
                    
                if ar_status.map(|s| s.success()).unwrap_or(false) {
                    println!("cargo:rustc-link-search=native={}", out_dir);
                    println!("cargo:rustc-link-lib=static=manifest");
                } else {
                    println!("cargo:rustc-link-arg={}", object_path);
                }
            } else {
                panic!("Failed to compile manifest data with both clang and gcc");
            }
        }
    }
}