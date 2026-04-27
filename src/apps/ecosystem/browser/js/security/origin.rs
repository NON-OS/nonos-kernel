extern crate alloc;
use alloc::string::String;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl Origin {
    pub fn from_url(url: &str) -> Self {
        let mut rest = url;
        let scheme = if let Some(i) = rest.find("://") {
            let s = String::from(&rest[..i]);
            rest = &rest[i + 3..];
            s
        } else {
            rest = url;
            String::from("https")
        };
        let host_part = if let Some(i) = rest.find('/') { &rest[..i] } else { rest };
        let (host, port) = if let Some(i) = host_part.find(':') {
            (
                String::from(&host_part[..i]),
                host_part[i + 1..].parse().unwrap_or(default_port(&scheme)),
            )
        } else {
            (String::from(host_part), default_port(&scheme))
        };
        Self { scheme, host, port }
    }

    pub fn same_origin(&self, other: &Self) -> bool {
        self.scheme == other.scheme && self.host == other.host && self.port == other.port
    }

    pub fn is_opaque(&self) -> bool {
        self.scheme == "data" || self.scheme == "blob" || self.scheme == "about"
    }

    pub fn serialized(&self) -> String {
        if self.port == default_port(&self.scheme) {
            alloc::format!("{}://{}", self.scheme, self.host)
        } else {
            alloc::format!("{}://{}:{}", self.scheme, self.host, self.port)
        }
    }
}

fn default_port(scheme: &str) -> u16 {
    match scheme {
        "http" => 80,
        "https" => 443,
        "ftp" => 21,
        _ => 0,
    }
}
