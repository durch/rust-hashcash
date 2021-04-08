#[macro_use]
extern crate log;

use chrono::{DateTime, NaiveDateTime, Utc};
use digest::Digest;
use rand::distributions::{Alphanumeric, Distribution};
use rand::thread_rng;
use sha1::Sha1;
use sha3::Sha3_256;
use std::convert::TryFrom;
use std::fmt;
use std::time::SystemTime;

simpl::err!(HcError,
    {
        Int@std::num::ParseIntError;
        Time@std::time::SystemTimeError;
    }
);

fn to_iso_32bit_safe(timestamp_secs: u32, short: bool) -> String {
    let mut seconds = timestamp_secs;
    let mut minutes = seconds / 60;
    seconds -= minutes * 60;
    let mut hours = minutes / 60;
    minutes -= hours * 60;
    let mut days = hours / 24;
    hours -= days * 24;
    let mut year = 1970;
    let mut day_of_week = 4;
    let mut mnth = 0;
    loop {
        let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let days_in_year = if leap_year { 366 } else { 365 };
        if days >= days_in_year {
            day_of_week += if leap_year { 2 } else { 1 };
            days -= days_in_year;
            if day_of_week >= 7 {
                day_of_week -= 7;
            }
            year += 1;
        } else {
            day_of_week += days;
            day_of_week %= 7;

            let days_in_month = vec![31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
            for month in 0..12 {
                mnth = month;
                let mut dim = *days_in_month.get(month).unwrap();

                /* add a day to February if this is a leap year */
                if month == 1 && leap_year {
                    dim += 1;
                }

                if days >= dim {
                    days -= dim;
                } else {
                    break;
                }
            }
            mnth += 1;
            days += 1;
            break;
        }
    }
    if short {
        format!("{}-{:02}-{:02}", year, mnth, days)
    } else {
        format!(
            "{}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            year, mnth, days, hours, minutes, seconds
        )
    }
}

fn _hash<T: Digest>(hasher: &mut T, challenge: &str, bits: u32) -> String {
    let mut counter = 0;
    let hex_digits = ((bits as f32) / 4.).ceil() as usize;
    let zeros = String::from_utf8(vec![b'0'; hex_digits]).unwrap();
    loop {
        hasher.input(&format!("{}:{:x}", challenge, counter).as_bytes());
        let result = hex::encode(hasher.result_reset());
        if result[..hex_digits] == zeros {
            debug!("{}", &result);
            return format!("{:x}", counter);
        };
        counter += 1
    }
}

/// Answer a generalized hashcash version 1 challenge
/// Hashcash requires stamps of form 'ver:bits:date:res:ext:rand:counter'
/// This internal function accepts a generalized prefix 'challenge',
/// and returns only a suffix that produces the requested SHA leading zeros.
///
/// NOTE: Number of requested bits is rounded up to the nearest multiple of 4
fn _mint(challenge: &str, bits: u32) -> String {
    if cfg!(feature = "sha1") {
        let mut hasher = Sha1::new();
        _hash(&mut hasher, challenge, bits)
    } else {
        let mut hasher = Sha3_256::new();
        _hash(&mut hasher, challenge, bits)
    }
}

/// Check whether a stamp is valid
///
/// Optionally, the stamp may be checked for a specific resource, and/or
/// it may require a minimum bit value, and/or it may be checked for
/// expiration, and/or it may be checked for double spending.
///
/// If 'check_expiration' is specified, it should contain an expiration DateTime<Utc>
///
/// NOTE: Every valid (version 1) stamp must meet its claimed bit value
/// NOTE: Check floor of 4-bit multiples (overly permissive in acceptance)
///     """
pub fn check_with_params(
    stamp: &str,
    resource: Option<&str>,
    bits: Option<u32>,
    expiration: Option<DateTime<Utc>>,
) -> Result<bool, HcError> {
    let stamp = Stamp::try_from(stamp)?;
    if !stamp.check_version() {
        return Err(HcError::from(
            format!(
                "Can only check version 1 stamp, got version {}",
                stamp.version
            )
            .as_str(),
        ));
    }
    if !stamp.check_resource(resource) {
        return Ok(false);
    }
    if !stamp.check_bits(bits) {
        return Ok(false);
    }
    if !stamp.check_expiration(expiration) {
        return Ok(false);
    }
    Ok(stamp.check())
}

/// Check whether a stamp is valid
pub fn check(stamp: &str) -> Result<bool> {
    check_with_params(stamp, None, None, None)
}

#[derive(Debug)]
pub struct Stamp {
    version: String,
    claim: u32,
    ts: String,
    resource: String,
    ext: String,
    rand: String,
    counter: String,
}

impl Stamp {
    fn check_version(&self) -> bool {
        self.version == "1"
    }

    fn check_resource(&self, resource: Option<&str>) -> bool {
        if let Some(resource) = resource {
            self.resource == resource
        } else {
            true
        }
    }

    fn check_bits(&self, bits: Option<u32>) -> bool {
        if let Some(bits) = bits {
            bits <= self.claim
        } else {
            true
        }
    }

    fn check_expiration(&self, expiration: Option<DateTime<Utc>>) -> bool {
        if let Some(expiration) = expiration {
            Utc::now() < expiration
        } else {
            true
        }
    }

    fn hex_digits(&self) -> usize {
        ((self.claim as f32) / 4.).floor() as usize
    }

    fn zeroes(&self) -> String {
        String::from_utf8(vec![b'0'; self.hex_digits()]).unwrap()
    }

    fn _check<T: Digest>(&self, hasher: &mut T) -> bool {
        debug!("{}", self.to_string());
        hasher.input(&self.to_string().as_bytes());
        let result = hex::encode(hasher.result_reset());
        debug!("{}", &result);
        result[..self.hex_digits()] == self.zeroes()
    }

    fn check(&self) -> bool {
        if cfg!(feature = "sha1") {
            let mut hasher = Sha1::new();
            self._check(&mut hasher)
        } else {
            let mut hasher = Sha3_256::new();
            self._check(&mut hasher)
        }
    }

    fn format(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.version, self.claim, self.ts, self.resource, self.ext, self.rand, self.counter
        )
    }

    /// Like mint() but for webassembly, 32bit system safe
    pub fn mint_wasm(
        resource: Option<&str>,
        bits: Option<u32>,
        now: Option<u32>,
        ext: Option<&str>,
        saltchars: Option<usize>,
        stamp_seconds: bool,
    ) -> Result<Self> {
        let version = "1";

        let timestamp_secs = if let Some(now) = now {
            now
        } else {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs() as u32
        };
        let ts = if stamp_seconds {
            to_iso_32bit_safe(timestamp_secs, false)
        } else {
            to_iso_32bit_safe(timestamp_secs, true)
        };
        let bits = bits.unwrap_or(20);
        let ext = ext.unwrap_or("");
        let saltchars = saltchars.unwrap_or(8);
        let rand = Alphanumeric
            .sample_iter(thread_rng())
            .take(saltchars)
            .collect();
        let resource = resource.unwrap_or("");
        let challenge = format!("{}:{}:{}:{}:{}:{}", version, bits, ts, resource, ext, rand);

        Ok(Stamp {
            version: version.to_string(),
            claim: bits,
            ts,
            resource: resource.to_string(),
            ext: ext.to_string(),
            rand,
            counter: _mint(&challenge, bits),
        })
    }

    /// Mint a new hashcash stamp for 'resource' with 'bits' of collision
    /// 20 bits of collision is the default.
    ///
    /// 'ext' lets you add your own extensions to a minted stamp.  Specify an
    /// extension as a string of form 'name1=2,3;name2;name3=var1=2,2,val'
    ///
    /// 'saltchars' specifies the length of the salt used; this version defaults
    /// 8 chars, rather than the C version's 16 chars.  This still provides about
    /// 17 million salts per resource, per timestamp, before birthday paradox
    /// collisions occur.  Really paranoid users can use a larger salt though.
    ///
    /// 'stamp_seconds' lets you add the option time elements to the datestamp.
    /// If you want more than just day, you get all the way down to seconds,
    /// even though the spec also allows hours/minutes without seconds.
    pub fn mint(
        resource: Option<&str>,
        bits: Option<u32>,
        now: Option<i64>,
        ext: Option<&str>,
        saltchars: Option<usize>,
        stamp_seconds: bool,
    ) -> Result<Self> {
        let version = "1";
        let now = if let Some(now) = now {
            DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(now, 0), Utc)
        } else {
            Utc::now()
        };
        let ts = if stamp_seconds {
            now.format("%Y%m%d%H%M%S")
        } else {
            now.format("%Y%m%d")
        };
        let bits = bits.unwrap_or(20);
        let ext = ext.unwrap_or("");
        let saltchars = saltchars.unwrap_or(8);
        let rand = Alphanumeric
            .sample_iter(thread_rng())
            .take(saltchars)
            .collect();
        let resource = resource.unwrap_or("");
        let challenge = format!("{}:{}:{}:{}:{}:{}", version, bits, ts, resource, ext, rand);

        Ok(Stamp {
            version: version.to_string(),
            claim: bits,
            ts: ts.to_string(),
            resource: resource.to_string(),
            ext: ext.to_string(),
            rand,
            counter: _mint(&challenge, bits),
        })
    }

    pub fn with_secs() -> Result<Self> {
        Self::mint(None, None, None, None, None, true)
    }

    pub fn with_resource(resource: &str, stamp_seconds: bool) -> Result<Self> {
        Self::mint(Some(resource), None, None, None, None, stamp_seconds)
    }

    pub fn with_bits(bits: u32, stamp_seconds: bool) -> Result<Self> {
        Self::mint(None, Some(bits), None, None, None, stamp_seconds)
    }

    pub fn with_resource_and_bits(resource: &str, bits: u32, stamp_seconds: bool) -> Result<Self> {
        Self::mint(Some(resource), Some(bits), None, None, None, stamp_seconds)
    }
}

impl TryFrom<&str> for Stamp {
    type Error = HcError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let stamp_vec = value.split(':').collect::<Vec<&str>>();
        if stamp_vec.len() != 7 {
            return Err(HcError::from(
                format!("Malformed stamp, expected 6 parts, got {}", stamp_vec.len()).as_str(),
            ));
        }
        Ok(Stamp {
            version: stamp_vec[0].to_string(),
            claim: stamp_vec[1].parse()?,
            ts: stamp_vec[2].to_string(),
            resource: stamp_vec[3].to_string(),
            ext: stamp_vec[4].to_string(),
            rand: stamp_vec[5].to_string(),
            counter: stamp_vec[6].to_string(),
        })
    }
}

impl fmt::Display for Stamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format())
    }
}

impl Default for Stamp {
    fn default() -> Self {
        Self::mint(None, None, None, None, None, false).unwrap()
    }
}

mod test {
    use crate::check;
    use crate::Stamp;
    use crate::to_iso_32bit_safe;

    #[test]
    fn test_default() {
        let stamp = Stamp::default();
        let result = check(&stamp.to_string());
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_with_secs() {
        let stamp = Stamp::with_secs();
        assert!(stamp.is_ok());
        let result = check(&stamp.unwrap().to_string());
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_with_resource() {
        let stamp = Stamp::with_resource("test", false);
        assert!(stamp.is_ok());
        let result = check(&stamp.unwrap().to_string());
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_with_resource_and_seconds() {
        let stamp = Stamp::with_resource("test", true);
        assert!(stamp.is_ok());
        let result = check(&stamp.unwrap().to_string());
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_with_bits() {
        let stamp = Stamp::with_bits(16, false);
        assert!(stamp.is_ok());
        let result = check(&stamp.unwrap().to_string());
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_with_bits_and_seconds() {
        let stamp = Stamp::with_bits(16, true);
        assert!(stamp.is_ok());
        let result = check(&stamp.unwrap().to_string());
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_with_resource_and_bits() {
        let stamp = Stamp::with_resource_and_bits("test", 16, false);
        assert!(stamp.is_ok());
        let result = check(&stamp.unwrap().to_string());
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_with_resource_and_bits_and_seconds() {
        let stamp = Stamp::with_resource_and_bits("test", 16, true);
        assert!(stamp.is_ok());
        let result = check(&stamp.unwrap().to_string());
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_mint() {
        let stamp = Stamp::mint(
            Some("test"),
            Some(15),
            None,
            Some("name1=2"),
            Some(12),
            false,
        );
        assert!(stamp.is_ok());
        let result = check(&stamp.unwrap().to_string());
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_check() {
        assert!(check("1:20:20202116:test::Z4p8WaiO:31c14").unwrap());
        assert!(!check("1:20:20202116:test1::Z4p8WaiO:31c14").unwrap());
        assert!(!check("1:20:20202116:test::z4p8WaiO:31c14").unwrap());
        assert!(!check("1:20:20202116:test::Z4p8WaiO:31C14").unwrap());
        assert!(check("0:20:20202116:test::Z4p8WaiO:31c14").is_err());
        assert!(!check("1:19:20202116:test::Z4p8WaiO:31c14").unwrap());
        assert!(!check("1:20:20202115:test::Z4p8WaiO:31c14").unwrap());
    }

    #[test]
    fn test_to_iso() {
        assert_eq!(to_iso_32bit_safe(1592565184, false), "2020-06-19T11:13:04Z")
    }
}
