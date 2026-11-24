//! RFC 6238 TOTP (SHA1/256/512, 6 or 8 digits, any period) from otpauth:// URIs.
use crate::{Error, Result};
use hmac::{Hmac, KeyInit, Mac};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algo {
    Sha1,
    Sha256,
    Sha512,
}

pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    pub algo: Algo,
    pub digits: u32,
    pub period: u64,
}

fn decode_secret(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace() && *c != '=' && *c != '-').collect::<String>().to_ascii_uppercase();
    data_encoding::BASE32_NOPAD
        .decode(clean.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| Error::Invalid("TOTP secret is not valid base32".into()))
}

impl Totp {
    /// Parses an `otpauth://totp/...` URI or a bare base32 secret (SHA1/6/30 defaults).
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if !s.to_ascii_lowercase().starts_with("otpauth://") {
            return Ok(Self { secret: decode_secret(s)?, algo: Algo::Sha1, digits: 6, period: 30 });
        }
        let u = url::Url::parse(s).map_err(|_| Error::Invalid("bad otpauth URI".into()))?;
        if u.host_str().map(str::to_ascii_lowercase).as_deref() != Some("totp") {
            return Err(Error::Invalid("only otpauth://totp is supported".into()));
        }
        let (mut secret, mut algo, mut digits, mut period) = (None, Algo::Sha1, 6, 30);
        for (k, v) in u.query_pairs() {
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(decode_secret(&v)?),
                "algorithm" => {
                    algo = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algo::Sha1,
                        "SHA256" => Algo::Sha256,
                        "SHA512" => Algo::Sha512,
                        _ => return Err(Error::Invalid("unsupported TOTP algorithm".into())),
                    }
                }
                "digits" => digits = v.parse().map_err(|_| Error::Invalid("bad digits".into()))?,
                "period" => period = v.parse().map_err(|_| Error::Invalid("bad period".into()))?,
                _ => {}
            }
        }
        if !(digits == 6 || digits == 8) || period == 0 {
            return Err(Error::Invalid("TOTP needs 6 or 8 digits and a period > 0".into()));
        }
        let secret = secret.ok_or_else(|| Error::Invalid("otpauth URI has no secret".into()))?;
        Ok(Self { secret, algo, digits, period })
    }

    fn mac(&self, msg: &[u8]) -> Zeroizing<Vec<u8>> {
        macro_rules! h {
            ($d:ty) => {{
                let mut m = <Hmac<$d> as KeyInit>::new_from_slice(&self.secret).expect("any key length");
                m.update(msg);
                Zeroizing::new(m.finalize().into_bytes().to_vec())
            }};
        }
        match self.algo {
            Algo::Sha1 => h!(sha1::Sha1),
            Algo::Sha256 => h!(sha2::Sha256),
            Algo::Sha512 => h!(sha2::Sha512),
        }
    }

    /// Code for unix time `t`.
    pub fn code_at(&self, t: u64) -> String {
        let h = self.mac(&(t / self.period).to_be_bytes());
        let o = (h[h.len() - 1] & 0x0f) as usize;
        let bin = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]);
        format!("{:0width$}", bin % 10u32.pow(self.digits), width = self.digits as usize)
    }

    /// (current code, seconds until it changes)
    pub fn now(&self) -> (String, u64) {
        let t = crate::vault::now().max(0) as u64;
        (self.code_at(t), self.period - t % self.period)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b32(s: &[u8]) -> String {
        data_encoding::BASE32_NOPAD.encode(s)
    }

    /// RFC 6238 appendix B test vectors (8 digits).
    #[test]
    fn rfc6238_vectors() {
        let cases = [
            ("SHA1", &b"12345678901234567890"[..], [(59u64, "94287082"), (1111111109, "07081804"), (20000000000, "65353130")]),
            ("SHA256", &b"12345678901234567890123456789012"[..], [(59, "46119246"), (1111111109, "68084774"), (20000000000, "77737706")]),
            (
                "SHA512",
                &b"1234567890123456789012345678901234567890123456789012345678901234"[..],
                [(59, "90693936"), (1111111109, "25091201"), (20000000000, "47863826")],
            ),
        ];
        for (alg, key, vecs) in cases {
            let t = Totp::parse(&format!("otpauth://totp/x?secret={}&algorithm={alg}&digits=8", b32(key))).unwrap();
            for (time, code) in vecs {
                assert_eq!(t.code_at(time), code, "{alg} @ {time}");
            }
        }
    }

    #[test]
    fn bare_secret_and_errors() {
        let t = Totp::parse("JBSW Y3DP EHPK 3PXP").unwrap();
        assert_eq!((t.digits, t.period, t.algo), (6, 30, Algo::Sha1));
        assert_eq!(t.now().0.len(), 6);
        assert!(Totp::parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(Totp::parse("otpauth://totp/x").is_err());
        assert!(Totp::parse("not base32 !!").is_err());
    }
}
