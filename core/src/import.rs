//! Import from KeePass KDBX4 and Bitwarden unencrypted JSON exports.
use crate::model::{CustomField, Entry};
use crate::vault::Vault;
use crate::{Error, Result};
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct ImportSummary {
    pub imported: usize,
    pub skipped: usize,
}

/// Duplicate key: same title + username + URL (first URL, case-insensitive).
fn dup_key(e: &Entry) -> (String, String, String) {
    (e.title.clone(), e.username.clone(), e.urls.first().map(|u| u.trim_end_matches('/').to_lowercase()).unwrap_or_default())
}

/// Adds entries to the vault, skipping duplicates of existing or earlier entries.
pub fn import_entries(v: &mut Vault, entries: Vec<Entry>) -> Result<ImportSummary> {
    let mut seen: HashSet<_> = v
        .list()?
        .iter()
        .flat_map(|i| i.siblings.iter().filter_map(|s| s.entry.as_ref().map(dup_key)))
        .collect();
    let mut sum = ImportSummary::default();
    for e in entries {
        if seen.insert(dup_key(&e)) {
            v.put(None, e)?;
            sum.imported += 1;
        } else {
            sum.skipped += 1;
        }
    }
    Ok(sum)
}

const KP_STANDARD: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];
const KP_OTP: [&str; 2] = ["otp", "TimeOtp-Secret-Base32"];

pub fn parse_kdbx(data: &[u8], password: &str) -> Result<Vec<Entry>> {
    use keepass::{Database, DatabaseKey};
    let db = Database::parse(data, DatabaseKey::new().with_password(password))
        .map_err(|e| Error::Invalid(format!("cannot open KeePass file: {e}")))?;
    let bin = db.meta.recyclebin_uuid;
    let mut out = Vec::new();
    for en in db.iter_all_entries() {
        if bin.is_some() && Some(en.parent().id().uuid()) == bin {
            continue;
        }
        let f = |k: &str| en.get(k).unwrap_or("").to_string();
        let mut e = Entry::default();
        e.title = f("Title");
        e.username = f("UserName");
        e.password = f("Password");
        e.notes = f("Notes");
        if !f("URL").is_empty() {
            e.urls.push(f("URL"));
        }
        e.totp = KP_OTP.iter().find_map(|k| en.get(k).filter(|v| !v.is_empty()).map(str::to_string));
        let mut names: Vec<&String> = en.fields.keys().filter(|k| !KP_STANDARD.contains(&k.as_str()) && !KP_OTP.contains(&k.as_str())).collect();
        names.sort();
        for k in names {
            if k.starts_with("TimeOtp-") || k.starts_with("HmacOtp-") {
                continue;
            }
            e.custom_fields.push(CustomField { name: k.clone(), value: f(k) });
        }
        out.push(e);
    }
    Ok(out)
}

#[derive(Deserialize)]
struct BwExport {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    items: Vec<BwItem>,
}

#[derive(Deserialize)]
struct BwItem {
    #[serde(rename = "type")]
    kind: u8,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    fields: Option<Vec<BwField>>,
    #[serde(default)]
    login: Option<BwLogin>,
}

#[derive(Deserialize)]
struct BwField {
    name: Option<String>,
    value: Option<String>,
}

#[derive(Deserialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Option<Vec<BwUri>>,
}

#[derive(Deserialize)]
struct BwUri {
    uri: Option<String>,
}

/// Login items (type 1) of an unencrypted Bitwarden JSON export.
pub fn parse_bitwarden(data: &[u8]) -> Result<Vec<Entry>> {
    let ex: BwExport = serde_json::from_slice(data).map_err(|e| Error::Invalid(format!("not a Bitwarden JSON export: {e}")))?;
    if ex.encrypted {
        return Err(Error::Invalid("encrypted Bitwarden exports are not supported; export as unencrypted JSON".into()));
    }
    Ok(ex
        .items
        .into_iter()
        .filter(|i| i.kind == 1)
        .map(|i| {
            let l = i.login.unwrap_or(BwLogin { username: None, password: None, totp: None, uris: None });
            let mut e = Entry::default();
            e.title = i.name.unwrap_or_default();
            e.username = l.username.unwrap_or_default();
            e.password = l.password.unwrap_or_default();
            e.notes = i.notes.unwrap_or_default();
            e.totp = l.totp.filter(|t| !t.is_empty());
            e.urls = l.uris.unwrap_or_default().into_iter().filter_map(|u| u.uri).collect();
            e.custom_fields = i
                .fields
                .unwrap_or_default()
                .into_iter()
                .map(|f| CustomField { name: f.name.unwrap_or_default(), value: f.value.unwrap_or_default() })
                .collect();
            e
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KDBX: &[u8] = include_bytes!("../tests/fixtures/keepass4.kdbx");
    const BW: &[u8] = include_bytes!("../tests/fixtures/bitwarden.json");

    #[test]
    fn kdbx4_fixture() {
        let es = parse_kdbx(KDBX, "fixture-pw").unwrap();
        assert_eq!(es.len(), 3, "recycle bin entries are skipped");
        let gh = es.iter().find(|e| e.title == "GitHub").unwrap();
        assert_eq!(gh.username, "octo");
        assert_eq!(gh.password, "gh-secret-1");
        assert_eq!(gh.urls, vec!["https://github.com/login"]);
        assert_eq!(gh.notes, "work account");
        assert!(gh.totp.as_deref().unwrap().contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(gh.custom_fields, vec![CustomField { name: "PIN".into(), value: "4321".into() }]);
        assert!(parse_kdbx(KDBX, "wrong").is_err());
    }

    #[test]
    fn bitwarden_fixture() {
        let es = parse_bitwarden(BW).unwrap();
        assert_eq!(es.len(), 2, "only login items");
        assert_eq!(es[0].urls.len(), 2);
        assert_eq!(es[0].custom_fields[0].value, "abc-123");
        assert_eq!(crate::totp::Totp::parse(es[0].totp.as_ref().unwrap()).unwrap().digits, 8);
    }

    #[test]
    fn import_skips_duplicates() {
        let mut v = crate::vault::tests::new_vault();
        let s = import_entries(&mut v, parse_kdbx(KDBX, "fixture-pw").unwrap()).unwrap();
        assert_eq!(s, ImportSummary { imported: 2, skipped: 1 });
        let s = import_entries(&mut v, parse_bitwarden(BW).unwrap()).unwrap();
        assert_eq!(s, ImportSummary { imported: 1, skipped: 1 });
        let s = import_entries(&mut v, parse_bitwarden(BW).unwrap()).unwrap();
        assert_eq!(s, ImportSummary { imported: 0, skipped: 2 });
        assert_eq!(v.list().unwrap().len(), 3);
    }
}
