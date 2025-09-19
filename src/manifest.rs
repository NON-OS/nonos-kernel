//! Kernel manifest and cryptographic data embedded at compile time

// The build script generates these symbols in the object files
extern "C" {
    static __nonos_manifest_start: [u8; 0];
    static __nonos_manifest_end: [u8; 0];
    static __nonos_signature_start: [u8; 0]; 
    static __nonos_signature_end: [u8; 0];
}

/// Get the embedded manifest data
pub fn get_manifest_data() -> &'static [u8] {
    unsafe {
        let start = __nonos_manifest_start.as_ptr();
        let end = __nonos_manifest_end.as_ptr();
        let len = end.offset_from(start) as usize;
        core::slice::from_raw_parts(start, len)
    }
}

/// Get the embedded signature data  
pub fn get_signature_data() -> &'static [u8] {
    unsafe {
        let start = __nonos_signature_start.as_ptr();
        let end = __nonos_signature_end.as_ptr();
        let len = end.offset_from(start) as usize;
        core::slice::from_raw_parts(start, len)
    }
}