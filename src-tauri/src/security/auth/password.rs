//! Password rules: length limits and the zxcvbn strength estimate that
//! gates new master passwords.

use serde::Serialize;

use crate::domain::error::{Error, Result};

pub const MIN_PASSWORD_LEN: usize = 8;

pub fn validate_new_password(pw: &str) -> Result<()> {
    if pw.chars().count() < MIN_PASSWORD_LEN {
        return Err(Error::Invalid(format!("Passwords must be at least {MIN_PASSWORD_LEN} characters.")));
    }
    if pw.len() > 1024 {
        return Err(Error::Invalid("Password is too long.".into()));
    }
    Ok(())
}

/// Minimum zxcvbn score (0–4) for the master password. 3 = "safely
/// unguessable": strong protection against an offline attack on Argon2id.
pub const MIN_MASTER_SCORE: u8 = 3;

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PasswordStrength {
    /// 0 (too guessable) ... 4 (very unguessable)
    pub score: u8,
    pub warning: Option<String>,
    pub suggestions: Vec<String>,
}

/// zxcvbn estimate of how guessable `pw` is (dictionary words, names,
/// keyboard patterns, dates, repeats, l33t substitutions...).
pub fn password_strength(pw: &str) -> PasswordStrength {
    if pw.is_empty() || pw.len() > 1024 {
        return PasswordStrength { score: 0, warning: None, suggestions: vec![] };
    }
    // zxcvbn's matching gets very slow on long inputs; like the reference
    // implementation, only the first 100 characters are analysed. Anything
    // longer that passes those is a long passphrase anyway.
    let pw: &str = match pw.char_indices().nth(100) {
        Some((i, _)) => &pw[..i],
        None => pw,
    };
    let e = zxcvbn::zxcvbn(pw, &["dirshield", "dir shield", "folder", "lock"]);
    let (warning, suggestions) = match e.feedback() {
        Some(f) => (f.warning().map(|w| w.to_string()), f.suggestions().iter().map(|s| s.to_string()).collect()),
        None => (None, vec![]),
    };
    PasswordStrength { score: e.score().into(), warning, suggestions }
}

/// Rules for a new master password: the length rules plus a zxcvbn check.
/// The master password is the only thing between an offline attacker holding
/// the database and every vault key, so "eight characters" is not enough.
pub fn validate_master_password(pw: &str) -> Result<()> {
    validate_new_password(pw)?;
    let s = password_strength(pw);
    if s.score < MIN_MASTER_SCORE {
        let why = s.warning.map(|w| format!(" {w}")).unwrap_or_default();
        return Err(Error::Invalid(format!("This master password is too easy to guess.{why} Try a longer passphrase of several unrelated words.")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn strength_is_fast_on_long_input() {
        let long = "a1b2c3d4e5".repeat(100);
        let t = std::time::Instant::now();
        password_strength(&long);
        assert!(t.elapsed() < Duration::from_secs(2), "took {:?}", t.elapsed());
    }
}
