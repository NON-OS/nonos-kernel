extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SriAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone)]
pub struct SriHash {
    pub algorithm: SriAlgorithm,
    pub digest: String,
}

pub fn parse_integrity(attr: &str) -> Vec<SriHash> {
    attr.split_whitespace()
        .filter_map(|token| {
            let (algo, digest) = token.split_once('-')?;
            let algorithm = match algo {
                "sha256" => SriAlgorithm::Sha256,
                "sha384" => SriAlgorithm::Sha384,
                "sha512" => SriAlgorithm::Sha512,
                _ => return None,
            };
            Some(SriHash { algorithm, digest: String::from(digest) })
        })
        .collect()
}

pub fn verify_integrity(hashes: &[SriHash], resource_hash: &str, algorithm: &SriAlgorithm) -> bool {
    if hashes.is_empty() {
        return true;
    }
    let matching: Vec<&SriHash> = hashes.iter().filter(|h| &h.algorithm == algorithm).collect();
    if matching.is_empty() {
        return true;
    }
    matching.iter().any(|h| h.digest == resource_hash)
}

pub fn strongest_algorithm(hashes: &[SriHash]) -> Option<&SriAlgorithm> {
    if hashes.iter().any(|h| h.algorithm == SriAlgorithm::Sha512) {
        return Some(&SriAlgorithm::Sha512);
    }
    if hashes.iter().any(|h| h.algorithm == SriAlgorithm::Sha384) {
        return Some(&SriAlgorithm::Sha384);
    }
    if hashes.iter().any(|h| h.algorithm == SriAlgorithm::Sha256) {
        return Some(&SriAlgorithm::Sha256);
    }
    None
}
