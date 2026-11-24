//! eTLD+1 matching using the compiled-in public suffix list (`psl` crate).

/// Returns the registrable domain (eTLD+1) of a host or URL, lowercased.
pub fn etld1(host_or_url: &str) -> Option<String> {
    let s = host_or_url.trim();
    let host = match url::Url::parse(s) {
        Ok(u) if u.host_str().is_some() => u.host_str()?.to_string(),
        _ => match url::Url::parse(&format!("https://{s}")) {
            Ok(u) => u.host_str()?.to_string(),
            Err(_) => return None,
        },
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return Some(host);
    }
    psl::domain_str(&host).map(str::to_string)
}

/// True if both resolve to the same eTLD+1.
pub fn same_site(a: &str, b: &str) -> bool {
    matches!((etld1(a), etld1(b)), (Some(x), Some(y)) if x == y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etld1_works() {
        assert_eq!(etld1("https://login.example.co.uk/path").as_deref(), Some("example.co.uk"));
        assert_eq!(etld1("www.github.com").as_deref(), Some("github.com"));
        assert!(same_site("https://a.foo.com", "foo.com"));
        assert!(!same_site("https://foo.com.evil.net", "foo.com"));
        assert_eq!(etld1("http://192.168.1.2:8080/").as_deref(), Some("192.168.1.2"));
    }
}
