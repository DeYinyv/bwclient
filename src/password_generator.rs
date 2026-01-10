use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordGeneratorOptions {
    pub length: u32,

    pub include_upper: bool,
    pub include_lower: bool,
    pub include_digits: bool,
    pub include_special: bool,

    pub min_numbers: u32,
    pub min_special: u32,
}

impl Default for PasswordGeneratorOptions {
    fn default() -> Self {
        Self {
            length: 16,
            include_upper: true,
            include_lower: true,
            include_digits: true,
            include_special: false,
            min_numbers: 3,
            // The UI defaults to 3 like Bitwarden, but when include_special is off we treat it as
            // effectively 0 (and disable the input).
            min_special: 3,
        }
    }
}

pub fn generate(opts: &PasswordGeneratorOptions) -> Result<String, String> {
    let length = opts.length as usize;
    if length == 0 {
        return Err("Length must be at least 1".to_string());
    }

    let effective_min_numbers = if opts.include_digits { opts.min_numbers as usize } else { 0 };
    let effective_min_special = if opts.include_special { opts.min_special as usize } else { 0 };

    if effective_min_numbers + effective_min_special > length {
        return Err("Minimum counts exceed length".to_string());
    }

    const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const DIGITS: &[u8] = b"0123456789";
    const SPECIAL: &[u8] = b"!@#$%^&*";

    let mut allowed: Vec<u8> = Vec::new();
    if opts.include_upper {
        allowed.extend_from_slice(UPPER);
    }
    if opts.include_lower {
        allowed.extend_from_slice(LOWER);
    }
    if opts.include_digits {
        allowed.extend_from_slice(DIGITS);
    }
    if opts.include_special {
        allowed.extend_from_slice(SPECIAL);
    }

    if allowed.is_empty() {
        return Err("Select at least one character set".to_string());
    }

    let mut rng = OsRng;
    let mut out: Vec<u8> = Vec::with_capacity(length);

    for _ in 0..effective_min_numbers {
        out.push(*DIGITS.choose(&mut rng).ok_or("digits set empty")?);
    }
    for _ in 0..effective_min_special {
        out.push(*SPECIAL.choose(&mut rng).ok_or("special set empty")?);
    }

    while out.len() < length {
        out.push(*allowed.choose(&mut rng).ok_or("allowed set empty")?);
    }

    out.shuffle(&mut rng);

    String::from_utf8(out).map_err(|_| "generated password is not valid UTF-8".to_string())
}
