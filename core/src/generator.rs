//! Password generator: length + character classes, uniform via rejection sampling.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenOptions {
    pub length: u32,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for GenOptions {
    fn default() -> Self {
        Self { length: 20, lower: true, upper: true, digits: true, symbols: true }
    }
}

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";

fn rand_below(n: u32) -> u32 {
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let v = getrandom::u32().expect("OS RNG unavailable");
        if v < zone {
            return v % n;
        }
    }
}

/// Generates a password containing at least one char of each selected class.
pub fn generate(o: &GenOptions) -> Result<Zeroizing<String>> {
    let classes: Vec<&[u8]> = [(o.lower, LOWER), (o.upper, UPPER), (o.digits, DIGITS), (o.symbols, SYMBOLS)]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, s)| s.as_bytes())
        .collect();
    if classes.is_empty() {
        return Err(Error::Invalid("select at least one character class".into()));
    }
    let len = o.length as usize;
    if len < classes.len() || len > 1024 {
        return Err(Error::Invalid("length out of range".into()));
    }
    let all: Vec<u8> = classes.concat();
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    for c in &classes {
        out.push(c[rand_below(c.len() as u32) as usize]);
    }
    while out.len() < len {
        out.push(all[rand_below(all.len() as u32) as usize]);
    }
    // Fisher-Yates so the guaranteed chars are not always first.
    for i in (1..out.len()).rev() {
        let j = rand_below(i as u32 + 1) as usize;
        out.swap(i, j);
    }
    Ok(Zeroizing::new(String::from_utf8(out.to_vec()).expect("ascii")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_length_and_classes() {
        for _ in 0..50 {
            let p = generate(&GenOptions { length: 8, lower: true, upper: false, digits: true, symbols: false }).unwrap();
            assert_eq!(p.len(), 8);
            assert!(p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
        }
    }

    #[test]
    fn rejects_bad_options() {
        assert!(generate(&GenOptions { length: 10, lower: false, upper: false, digits: false, symbols: false }).is_err());
        assert!(generate(&GenOptions { length: 2, ..Default::default() }).is_err());
    }
}
