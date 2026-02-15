use argon2::Algorithm;
use argon2::Argon2;
use argon2::Params;
use rand::{Rng, rng};

const SALT_LEN: usize = 16;

pub fn derive_aes_key(password: &str, salt: Option<[u8; SALT_LEN]>) -> ([u8; 32], [u8; SALT_LEN]) {
    let salt = match salt {
        Some(s) => s,
        None => {
            let mut rng = rng();
            let mut s = [0u8; 16];
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

#[test]
fn argon2_deterministic() {
    let password = "password";
    let (key, salt) = derive_aes_key(password, None);
    let (other, _) = derive_aes_key(password, Some(salt));
    assert_eq!(key, other);
}
