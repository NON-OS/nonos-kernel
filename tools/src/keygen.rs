use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use rand::rngs::OsRng;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const KEYS_DIR: &str = "/home/nonos/nonos-kernel/.keys";
const PRIVATE_KEY_FILE: &str = "signing.key";
const PUBLIC_KEY_FILE: &str = "signing.pub";
const BOOTLOADER_SIG_FILE: &str = "/home/nonos/nonos-kernel/nonos-boot/src/crypto/sig.rs";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("NONOS Production Key Generator v1.0");
    println!("====================================");
    
    let keypair = generate_keypair()?;
    let keys_dir = setup_keys_directory()?;
    
    let private_path = save_private_key(&keys_dir, &keypair.secret)?;
    let public_path = save_public_key(&keys_dir, &keypair.public)?;
    
    update_bootloader_public_key(&keypair.public)?;
    
    print_results(&keypair, &private_path, &public_path);
    print_build_instructions(&private_path);
    
    Ok(())
}

fn generate_keypair() -> Result<Keypair, Box<dyn std::error::Error>> {
    let mut csprng = OsRng;
    Ok(Keypair::generate(&mut csprng))
}

fn setup_keys_directory() -> Result<String, Box<dyn std::error::Error>> {
    let keys_dir = Path::new(KEYS_DIR);
    fs::create_dir_all(&keys_dir)?;
    
    let mut perms = fs::metadata(&keys_dir)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&keys_dir, perms)?;
    
    Ok(KEYS_DIR.to_string())
}

fn save_private_key(keys_dir: &str, secret_key: &SecretKey) -> Result<String, Box<dyn std::error::Error>> {
    let path = Path::new(keys_dir).join(PRIVATE_KEY_FILE);
    fs::write(&path, secret_key.to_bytes())?;
    
    let mut perms = fs::metadata(&path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&path, perms)?;
    
    Ok(path.to_string_lossy().to_string())
}

fn save_public_key(keys_dir: &str, public_key: &PublicKey) -> Result<String, Box<dyn std::error::Error>> {
    let path = Path::new(keys_dir).join(PUBLIC_KEY_FILE);
    fs::write(&path, public_key.to_bytes())?;
    
    Ok(path.to_string_lossy().to_string())
}

fn update_bootloader_public_key(public_key: &PublicKey) -> Result<(), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(BOOTLOADER_SIG_FILE)?;
    let key_bytes = public_key.to_bytes();
    
    let key_definition = format_key_array(&key_bytes);
    let updated_content = replace_key_in_content(&content, &key_definition)?;
    
    fs::write(BOOTLOADER_SIG_FILE, updated_content)?;
    Ok(())
}

fn format_key_array(key_bytes: &[u8; 32]) -> String {
    let formatted_bytes = key_bytes
        .chunks(4)
        .map(|chunk| {
            chunk
                .iter()
                .map(|b| format!("0x{:02x}", b))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .collect::<Vec<_>>()
        .join(",\n    ");
    
    format!(
        "pub const NONOS_SIGNING_KEY: [u8; 32] = [\n    {}\n];",
        formatted_bytes
    )
}

fn replace_key_in_content(content: &str, new_key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let start_marker = "pub const NONOS_SIGNING_KEY: [u8; 32] = [";
    let end_marker = "];";
    
    let start = content.find(start_marker)
        .ok_or("NONOS_SIGNING_KEY definition not found")?;
    
    let search_from = start + start_marker.len();
    let end = content[search_from..].find(end_marker)
        .ok_or("End of NONOS_SIGNING_KEY definition not found")?;
    
    let end_pos = search_from + end + end_marker.len();
    
    Ok(format!("{}{}{}", &content[..start], new_key, &content[end_pos..]))
}

fn print_results(keypair: &Keypair, private_path: &str, public_path: &str) {
    println!("✓ Ed25519 keypair generated successfully");
    println!("✓ Private key: {} bytes", keypair.secret.to_bytes().len());
    println!("✓ Public key:  {} bytes", keypair.public.to_bytes().len());
    println!("✓ Private key saved: {}", private_path);
    println!("✓ Public key saved:  {}", public_path);
    println!("✓ Bootloader updated with new public key");
}

fn print_build_instructions(private_path: &str) {
    println!("\n🔧 Production Build Setup:");
    println!("export NONOS_SIGNING_KEY={}", private_path);
    println!("\n🚀 Release Build Command:");
    println!("NONOS_SIGNING_KEY={} cargo +nightly build --release --target x86_64-nonos.json \\", private_path);
    println!("  -Z build-std=core,alloc,compiler_builtins \\");
    println!("  -Z build-std-features=compiler-builtins-mem");
}