use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-env-changed=NONOS_SIGNING_KEY");
    println!("cargo:rerun-if-changed=../assets/wallpapers/special-variant-9.png");

    generate_keys();
    generate_background_image();
    configure_uefi();
    configure_optimization();
    configure_crypto();
    configure_security();
    embed_build_info();
}

fn generate_keys() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("keys_generated.rs");

    let signing_key_path = env::var("NONOS_SIGNING_KEY").unwrap_or_else(|_| {
        let default = "keys/signing_key_v1.bin";
        if Path::new(default).exists() {
            String::from(default)
        } else {
            eprintln!("NOTE: No signing key found. Generating development key...");
            eprintln!("      For production, use: cargo run -p keygen -- --output keys/signing_key_v1.bin");

            let key_dir = Path::new("keys");
            if !key_dir.exists() {
                fs::create_dir_all(key_dir).expect("Cannot create keys directory");
            }

            let mut key = [0u8; 32];
            if let Ok(mut f) = fs::File::open("/dev/urandom") {
                use std::io::Read;
                let _ = f.read_exact(&mut key);
            } else {
                use std::time::{SystemTime, UNIX_EPOCH};
                let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
                for (i, byte) in key.iter_mut().enumerate() {
                    *byte = ((seed >> (i % 16 * 8)) & 0xFF) as u8 ^ (i as u8).wrapping_mul(17);
                }
            }

            fs::write(default, &key).expect("Cannot write development key");
            eprintln!("      Development key written to {}", default);
            String::from(default)
        }
    });

    println!("cargo:rerun-if-changed={}", signing_key_path);

    let key_data = fs::read(&signing_key_path).unwrap_or_else(|e| {
        panic!(
            "FATAL: Cannot read signing key at {}: {}\n\
             Generate a key with: ./tools/keygen/keygen.py --output {}",
            signing_key_path, e, signing_key_path
        )
    });

    if key_data.len() < 32 {
        panic!(
            "Signing key must be at least 32 bytes, got {}",
            key_data.len()
        );
    }

    let seed: [u8; 32] = key_data[..32].try_into().expect("seed length");
    let public_key = derive_ed25519_public_key(&seed);
    let key_id = compute_key_id(&public_key);

    let fingerprint = format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        key_id[0], key_id[1], key_id[2], key_id[3], key_id[4], key_id[5], key_id[6], key_id[7]
    );

    let build_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut file = fs::File::create(&dest_path).expect("Cannot create keys_generated.rs");

    writeln!(file, "pub const NONOS_PUBLIC_KEY: [u8; 32] = [").unwrap();
    write!(file, "    ").unwrap();
    for (i, byte) in public_key.iter().enumerate() {
        write!(file, "0x{:02x}", byte).unwrap();
        if i < 31 {
            write!(file, ", ").unwrap();
        }
        if (i + 1) % 8 == 0 && i < 31 {
            writeln!(file).unwrap();
            write!(file, "    ").unwrap();
        }
    }
    writeln!(file, "\n];").unwrap();

    writeln!(file, "pub const NONOS_KEY_ID: [u8; 32] = [").unwrap();
    write!(file, "    ").unwrap();
    for (i, byte) in key_id.iter().enumerate() {
        write!(file, "0x{:02x}", byte).unwrap();
        if i < 31 {
            write!(file, ", ").unwrap();
        }
        if (i + 1) % 8 == 0 && i < 31 {
            writeln!(file).unwrap();
            write!(file, "    ").unwrap();
        }
    }
    writeln!(file, "\n];").unwrap();

    writeln!(file, "pub const KEY_FINGERPRINT: &str = \"{}\";", fingerprint).unwrap();
    writeln!(file, "pub const BUILD_TIMESTAMP: u64 = {};", build_timestamp).unwrap();
    writeln!(file, "pub const KEY_VERSION: u32 = 1;").unwrap();

    println!("cargo:rustc-env=NONOS_KEY_FINGERPRINT={}", fingerprint);
    eprintln!("NONOS key fingerprint: {}", fingerprint);
}

fn derive_ed25519_public_key(seed: &[u8; 32]) -> [u8; 32] {
    compute_ed25519_pubkey(seed)
}

fn compute_ed25519_pubkey(scalar: &[u8; 32]) -> [u8; 32] {
    let output = std::process::Command::new("python3")
        .arg("-c")
        .arg(format!(
            r#"
import sys
def secret_to_public(secret):
    try:
        from nacl.signing import SigningKey
        sk = SigningKey(secret)
        return bytes(sk.verify_key)
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        private_key = Ed25519PrivateKey.from_private_bytes(secret)
        return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    except ImportError:
        pass
    sys.stderr.write("ERROR: No Ed25519 library available. Install: pip3 install pynacl cryptography\n")
    sys.exit(1)

secret = bytes([{}])
pub = secret_to_public(secret)
print(','.join(str(b) for b in pub))
"#,
            scalar.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")
        ))
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let bytes: Vec<u8> = stdout
                .trim()
                .split(',')
                .filter_map(|s| s.parse().ok())
                .collect();
            if bytes.len() == 32 {
                let mut result = [0u8; 32];
                result.copy_from_slice(&bytes);
                return result;
            }
            panic!("Ed25519 public key derivation returned {} bytes, expected 32", bytes.len());
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            panic!("Ed25519 derivation failed: {}", stderr.trim());
        }
        Err(e) => {
            panic!("Cannot execute python3: {}", e);
        }
    }
}

fn compute_key_id(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("NONOS:KEYID:ED25519:v1");
    hasher.update(public_key);
    *hasher.finalize().as_bytes()
}

fn configure_uefi() {
    println!("cargo:rustc-link-arg=-nostdlib");
    println!("cargo:rustc-link-arg=-zmax-page-size=0x1000");
    println!("cargo:rustc-link-arg=-static");
    println!("cargo:rustc-link-arg=--gc-sections");

    if cfg!(target_os = "uefi") {
        println!("cargo:rustc-link-arg=/SUBSYSTEM:EFI_APPLICATION");
        println!("cargo:rustc-link-arg=/ENTRY:efi_main");
        println!("cargo:rustc-link-arg=/MERGE:.rdata=.data");
    }
}

fn configure_optimization() {
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    if profile == "release" {
        println!("cargo:rustc-env=CARGO_CFG_LTO=fat");
        println!("cargo:rustc-link-arg=-Os");
        println!("cargo:rustc-link-arg=--strip-all");
        println!("cargo:rustc-link-arg=-z,relro");
        println!("cargo:rustc-link-arg=-z,now");
        println!("cargo:rustc-link-arg=-z,noexecstack");
    }
}

fn configure_crypto() {
    if cfg!(feature = "efi-rng") {
        println!("cargo:rustc-cfg=feature=\"hardware_rng\"");
        println!("cargo:rustc-env=NONOS_HW_RNG=1");
    }
    println!("cargo:rustc-cfg=blake3_no_sse2");
    println!("cargo:rustc-cfg=blake3_no_sse41");
    println!("cargo:rustc-cfg=blake3_no_avx2");
    println!("cargo:rustc-cfg=blake3_no_avx512");
}

fn configure_security() {
    if cfg!(feature = "nonos-cet") {
        println!("cargo:rustc-link-arg=-fcf-protection=full");
        println!("cargo:rustc-env=NONOS_CET_ENABLED=1");
    }
    println!("cargo:rustc-link-arg=-fstack-protector-strong");
    println!("cargo:rustc-link-arg=-fpie");
    println!("cargo:rustc-link-arg=/DYNAMICBASE");
    println!("cargo:rustc-link-arg=/HIGHENTROPYVA");
    println!("cargo:rustc-link-arg=/NXCOMPAT");
}

fn embed_build_info() {
    let build_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| format!("{}", d.as_secs()))
        .unwrap_or_else(|_| "0".to_string());

    println!("cargo:rustc-env=NONOS_BUILD_TIME={build_time}");

    if let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
    {
        let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("cargo:rustc-env=NONOS_GIT_COMMIT={commit}");
    } else {
        println!("cargo:rustc-env=NONOS_GIT_COMMIT=unknown");
    }

    let rustc_version = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rustc-env=NONOS_RUSTC_VERSION={rustc_version}");
    println!("cargo:rustc-env=NONOS_BOOTLOADER_NAME=NONOS Bootloader");
    println!("cargo:rustc-env=NONOS_BOOTLOADER_VERSION=1.0.0");
}

fn generate_background_image() {
    use std::io::Write as IoWrite;

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("background_generated.rs");

    let wallpaper_path = Path::new("../assets/wallpapers/special-variant-9.png");

    if !wallpaper_path.exists() {
        eprintln!("NOTE: Wallpaper not found at {:?}, generating gradient fallback", wallpaper_path);
        generate_gradient_fallback(&dest_path);
        return;
    }

    let img = match image::open(wallpaper_path) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("NOTE: Cannot load wallpaper: {}, generating gradient fallback", e);
            generate_gradient_fallback(&dest_path);
            return;
        }
    };

    /*
     * Scale to 640x360 for bootloader - keeps binary small (~900KB raw)
     * Runtime will scale to screen resolution
     */
    let target_w = 640u32;
    let target_h = 360u32;

    let scaled = img.resize_exact(target_w, target_h, image::imageops::FilterType::Lanczos3);
    let rgba = scaled.to_rgba8();

    /* RLE compression for repeated pixels */
    let mut compressed: Vec<u8> = Vec::new();
    let pixels = rgba.as_raw();

    let mut i = 0;
    while i < pixels.len() {
        let r = pixels[i];
        let g = pixels[i + 1];
        let b = pixels[i + 2];
        let a = pixels[i + 3];

        let mut run = 1u8;
        while run < 255 && i + (run as usize * 4) < pixels.len() {
            let ni = i + (run as usize * 4);
            if pixels[ni] == r && pixels[ni + 1] == g && pixels[ni + 2] == b && pixels[ni + 3] == a {
                run += 1;
            } else {
                break;
            }
        }

        compressed.push(run);
        compressed.push(b);  /* BGR order for framebuffer */
        compressed.push(g);
        compressed.push(r);
        compressed.push(a);

        i += run as usize * 4;
    }

    eprintln!("Background: {}x{}, raw {}KB, compressed {}KB ({:.1}% ratio)",
        target_w, target_h,
        (target_w * target_h * 4) / 1024,
        compressed.len() / 1024,
        (compressed.len() as f64 / (target_w * target_h * 4) as f64) * 100.0
    );

    let mut file = fs::File::create(&dest_path).expect("Cannot create background_generated.rs");

    writeln!(file, "pub const BG_WIDTH: u32 = {};", target_w).unwrap();
    writeln!(file, "pub const BG_HEIGHT: u32 = {};", target_h).unwrap();
    writeln!(file, "pub const BG_COMPRESSED_LEN: usize = {};", compressed.len()).unwrap();
    writeln!(file, "").unwrap();
    writeln!(file, "#[allow(clippy::all)]").unwrap();
    writeln!(file, "pub static BG_COMPRESSED: [u8; {}] = [", compressed.len()).unwrap();

    for (idx, chunk) in compressed.chunks(16).enumerate() {
        write!(file, "    ").unwrap();
        for (i, byte) in chunk.iter().enumerate() {
            write!(file, "0x{:02x}", byte).unwrap();
            if idx * 16 + i < compressed.len() - 1 {
                write!(file, ",").unwrap();
            }
            if i < chunk.len() - 1 {
                write!(file, " ").unwrap();
            }
        }
        writeln!(file, "").unwrap();
    }
    writeln!(file, "];").unwrap();
}

fn generate_gradient_fallback(dest_path: &Path) {
    use std::io::Write as IoWrite;

    /*
     * Generate a nature-inspired gradient as fallback
     * Deep green to soft cyan, like early morning meadow
     */
    let w = 64u32;
    let h = 36u32;

    let mut compressed: Vec<u8> = Vec::new();

    for y in 0..h {
        for x in 0..w {
            let fx = x as f32 / w as f32;
            let fy = y as f32 / h as f32;

            /* Diagonal gradient: deep forest green to soft teal */
            let t = (fx + fy) / 2.0;
            let r = (10.0 + t * 30.0) as u8;
            let g = (30.0 + t * 60.0) as u8;
            let b = (20.0 + t * 50.0) as u8;

            compressed.push(1);  /* run length 1 */
            compressed.push(b);
            compressed.push(g);
            compressed.push(r);
            compressed.push(255);
        }
    }

    let mut file = fs::File::create(dest_path).expect("Cannot create background_generated.rs");

    writeln!(file, "pub const BG_WIDTH: u32 = {};", w).unwrap();
    writeln!(file, "pub const BG_HEIGHT: u32 = {};", h).unwrap();
    writeln!(file, "pub const BG_COMPRESSED_LEN: usize = {};", compressed.len()).unwrap();
    writeln!(file, "").unwrap();
    writeln!(file, "#[allow(clippy::all)]").unwrap();
    writeln!(file, "pub static BG_COMPRESSED: [u8; {}] = [", compressed.len()).unwrap();

    for (idx, chunk) in compressed.chunks(16).enumerate() {
        write!(file, "    ").unwrap();
        for (i, byte) in chunk.iter().enumerate() {
            write!(file, "0x{:02x}", byte).unwrap();
            if idx * 16 + i < compressed.len() - 1 {
                write!(file, ",").unwrap();
            }
        }
        writeln!(file, "").unwrap();
    }
    writeln!(file, "];").unwrap();
}
