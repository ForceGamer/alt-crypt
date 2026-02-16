use argon2::Algorithm;
use argon2::Argon2;
use argon2::Params;
use argon2::PasswordHasher;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use rand::{Rng, rng};

use crate::aes::AesKey;

const SALT_LEN: usize = 16;
pub type Salt = [u8; SALT_LEN];

pub fn derive_aes_key(password: &str, salt: Option<Salt>) -> (AesKey, Salt) {
    let salt = match salt {
        Some(s) => s,
        None => {
            let mut rng = rng();
            let mut s = [0u8; SALT_LEN];
            rng.fill_bytes(&mut s);
            s
        }
    };
    let mut output = [0u8; 32];
    let argon2 = Argon2::new(Algorithm::Argon2id, argon2::Version::V0x13, Params::DEFAULT);

    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut output)
        .unwrap();
    (output, salt)
}

pub fn hash_password(password: &str, salt_bytes: Option<Salt>) -> (String, Salt) {
    let salt_bytes = match salt_bytes {
        Some(s) => s,
        None => {
            let mut rng = rng();
            let mut s = [0u8; SALT_LEN];
            rng.fill_bytes(&mut s);
            s
        }
    };
    let argon2 = Argon2::new(Algorithm::Argon2id, argon2::Version::V0x13, Params::DEFAULT);
    let salt_b64 = BASE64_STANDARD.encode(&salt_bytes);
    let salt = argon2::password_hash::Salt::from_b64(&salt_b64).unwrap();

    let hash = argon2.hash_password(password.as_bytes(), salt).unwrap();
    (hash.to_string(), salt_bytes)
}

#[test]
fn argon2_reproduce() {
    let password = "password";
    let (key, salt) = derive_aes_key(password, None);
    let (other, _) = derive_aes_key(password, Some(salt));
    assert_eq!(key, other);
}
