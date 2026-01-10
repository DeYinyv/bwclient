use hmac::{Hmac, Mac};
use sha1::Sha1;
use url::Url;

#[derive(Debug, Clone)]
pub struct TotpConfig {
    secret: Vec<u8>,
    digits: u32,
    period: u64,
}

impl TotpConfig {
    pub fn period(&self) -> u64 {
        self.period
    }

    pub fn generate(&self, unix_seconds: u64) -> String {
        let counter = unix_seconds / self.period;
        let mut msg = [0u8; 8];
        msg.copy_from_slice(&counter.to_be_bytes());

        let mut mac = Hmac::<Sha1>::new_from_slice(&self.secret).expect("hmac key");
        mac.update(&msg);
        let digest = mac.finalize().into_bytes();

        let offset = (digest[19] & 0x0f) as usize;
        let bin = ((digest[offset] as u32 & 0x7f) << 24)
            | ((digest[offset + 1] as u32) << 16)
            | ((digest[offset + 2] as u32) << 8)
            | (digest[offset + 3] as u32);

        let modulo = 10u32.pow(self.digits.min(10));
        let code = bin % modulo;
        format!("{:0width$}", code, width = self.digits as usize)
    }
}

pub fn seconds_until_rollover(unix_seconds: u64, period: u64) -> u64 {
    let period = period.max(1);
    let rem = unix_seconds % period;
    let left = period.saturating_sub(rem);
    // If exactly on boundary, most UIs show full period.
    if left == 0 { period } else { left }
}

pub fn parse_totp(s: &str) -> Result<TotpConfig, String> {
    let raw = s.trim();
    if raw.is_empty() {
        return Err("empty TOTP".to_string());
    }

    if raw.to_lowercase().starts_with("otpauth://") {
        return parse_otpauth(raw);
    }

    let secret = decode_base32(raw)?;
    Ok(TotpConfig {
        secret,
        digits: 6,
        period: 30,
    })
}

fn parse_otpauth(raw: &str) -> Result<TotpConfig, String> {
    let url = Url::parse(raw).map_err(|e| format!("invalid otpauth url: {e}"))?;

    // Only accept otpauth://totp/... (Bitwarden-style)
    if url.scheme() != "otpauth" {
        return Err("otpauth url: invalid scheme".to_string());
    }
    if url.host_str().unwrap_or("") != "totp" {
        return Err("otpauth url: only totp is supported".to_string());
    }

    let mut secret_b32: Option<String> = None;
    let mut digits: u32 = 6;
    let mut period: u64 = 30;
    let mut algorithm: Option<String> = None;

    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "secret" => secret_b32 = Some(v.to_string()),
            "digits" => {
                if let Ok(d) = v.parse::<u32>() {
                    digits = d;
                }
            }
            "period" => {
                if let Ok(p) = v.parse::<u64>() {
                    period = p;
                }
            }
            "algorithm" => algorithm = Some(v.to_string()),
            _ => {}
        }
    }

    if let Some(a) = algorithm
        && a.to_uppercase() != "SHA1"
    {
        return Err(format!("unsupported TOTP algorithm: {a} (only SHA1 is supported)"));
    }

    let secret_b32 = secret_b32.ok_or_else(|| "otpauth url missing secret".to_string())?;
    let secret = decode_base32(&secret_b32)?;

    if !(6..=10).contains(&digits) {
        return Err("digits must be between 6 and 10".to_string());
    }

    Ok(TotpConfig {
        secret,
        digits,
        period: period.max(1),
    })
}

fn decode_base32(input: &str) -> Result<Vec<u8>, String> {
    // RFC 4648 base32, case-insensitive, ignore spaces and hyphens, allow '=' padding.
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut out: Vec<u8> = Vec::new();

    for ch in input.chars() {
        let c = match ch {
            'A'..='Z' | 'a'..='z' | '2'..='7' => ch.to_ascii_uppercase(),
            '=' => continue,
            ' ' | '\t' | '\n' | '\r' | '-' => continue,
            _ => return Err(format!("invalid base32 character: '{ch}'")),
        };

        let val: u8 = match c {
            'A' => 0,
            'B' => 1,
            'C' => 2,
            'D' => 3,
            'E' => 4,
            'F' => 5,
            'G' => 6,
            'H' => 7,
            'I' => 8,
            'J' => 9,
            'K' => 10,
            'L' => 11,
            'M' => 12,
            'N' => 13,
            'O' => 14,
            'P' => 15,
            'Q' => 16,
            'R' => 17,
            'S' => 18,
            'T' => 19,
            'U' => 20,
            'V' => 21,
            'W' => 22,
            'X' => 23,
            'Y' => 24,
            'Z' => 25,
            '2' => 26,
            '3' => 27,
            '4' => 28,
            '5' => 29,
            '6' => 30,
            '7' => 31,
            _ => return Err("invalid base32 character".to_string()),
        };

        bits = (bits << 5) | (val as u32);
        bit_count += 5;

        while bit_count >= 8 {
            let shift = bit_count - 8;
            let byte = ((bits >> shift) & 0xff) as u8;
            out.push(byte);
            bit_count -= 8;
            bits &= (1u32 << bit_count) - 1;
        }
    }

    if out.is_empty() {
        return Err("base32 secret decoded to empty".to_string());
    }

    Ok(out)
}
