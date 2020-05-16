use chrono::{DateTime, Utc};
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use rand::distributions::{Alphanumeric, Distribution};
use rand::thread_rng;
use std::convert::TryFrom;

simpl::err!(HcError,
    {Int@std::num::ParseIntError;}
);

///    """Mint a new hashcash stamp for 'resource' with 'bits' of collision
///     20 bits of collision is the default.
///
///     'ext' lets you add your own extensions to a minted stamp.  Specify an
///     extension as a string of form 'name1=2,3;name2;name3=var1=2,2,val'
///
///     'saltchars' specifies the length of the salt used; this version defaults
///     8 chars, rather than the C version's 16 chars.  This still provides about
///     17 million salts per resource, per timestamp, before birthday paradox
///     collisions occur.  Really paranoid users can use a larger salt though.
///
///     'stamp_seconds' lets you add the option time elements to the datestamp.
///     If you want more than just day, you get all the way down to seconds,
///     even though the spec also allows hours/minutes without seconds.
pub fn mint(
    resource: &str,
    bits: usize,
    now: Option<DateTime<Utc>>,
    ext: Option<&str>,
    saltchars: Option<usize>,
    stamp_seconds: bool,
) -> String {
    let ver = "1";
    let now = now.unwrap_or(Utc::now());
    let ts = if stamp_seconds {
        now.format("%Y%M%d%H%M%S")
    } else {
        now.format("%Y%M%d")
    };
    let ext = ext.unwrap_or("");
    let saltchars = saltchars.unwrap_or(8);
    let challenge = format!(
        "{}:{}:{}:{}:{}:{}",
        ver,
        bits,
        ts,
        resource,
        ext,
        _salt(saltchars)
    );
    format!("{}:{}", challenge, _mint(&challenge, bits))
}

/// Return a random string of length 'l'
fn _salt(l: usize) -> String {
    Alphanumeric.sample_iter(thread_rng()).take(l).collect()
}

//     Answer a 'generalized hashcash challenge'
//     Hashcash requires stamps of form 'ver:bits:date:res:ext:rand:counter'
//     This internal function accepts a generalized prefix 'challenge',
//     and returns only a suffix that produces the requested SHA leading zeros.
//
//     NOTE: Number of requested bits is rounded up to the nearest multiple of 4
fn _mint(challenge: &str, bits: usize) -> String {
    let mut counter = 0;
    let hex_digits = ((bits as f32) / 4.).ceil() as usize;
    let zeros = String::from_utf8(vec![b'0'; hex_digits]).unwrap();
    let mut hasher = Sha1::new();
    loop {
        // println!("{}:{:x}", challenge, counter);
        hasher.input_str(&format!("{}:{:x}", challenge, counter));
        // println!("{}", hasher.result_str());
        if hasher.result_str()[..hex_digits] == zeros {
            println!("{}", hasher.result_str());
            return format!("{:x}", counter);
        };
        hasher.reset();
        counter += 1
    }
}

/// Check whether a stamp is valid
///
///     Optionally, the stamp may be checked for a specific resource, and/or
///     it may require a minimum bit value, and/or it may be checked for
///     expiration, and/or it may be checked for double spending.
///
///     If 'check_expiration' is specified, it should contain the number of
///     seconds old a date field may be.
///
///     NOTE: Every valid (version 1) stamp must meet its claimed bit value
///     NOTE: Check floor of 4-bit multiples (overly permissive in acceptance)
///     """
pub fn check(
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

#[derive(Debug)]
struct Stamp {
    version: String,
    claim: u32,
    date: String,
    resource: String,
    ext: String,
    rand: String,
    counter: String,
}

impl Stamp {
    fn check_version(&self) -> bool {
        self.version == "1".to_string()
    }

    fn check_resource(&self, resource: Option<&str>) -> bool {
        if let Some(resource) = resource {
            self.resource == resource.to_string()
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

    fn check(&self) -> bool {
        let mut hasher = Sha1::new();
        println!("{}", self.to_string());
        hasher.input_str(&self.to_string());
        println!("{}", hasher.result_str());
        hasher.result_str()[..self.hex_digits()] == self.zeroes()
    }

    fn to_string(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.version, self.claim, self.date, self.resource, self.ext, self.rand, self.counter
        )
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
            date: stamp_vec[2].to_string(),
            resource: stamp_vec[3].to_string(),
            ext: stamp_vec[4].to_string(),
            rand: stamp_vec[5].to_string(),
            counter: stamp_vec[6].to_string(),
        })
    }
}
