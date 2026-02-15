use aws_lc_rs::aead::{AES_256_GCM, Aad, Nonce, RandomizedNonceKey};

use crate::argon2::derive_aes_key;

const TAG_LEN: usize = 16;

pub fn encrypt(data: &[u8], key: &[u8]) -> (Vec<u8>, Nonce) {
    let key = RandomizedNonceKey::new(&AES_256_GCM, key).unwrap();
    let mut in_out = Vec::from(data);

    let nonce = key
        .seal_in_place_append_tag(Aad::empty(), &mut in_out)
        .unwrap();
    (in_out, nonce)
}

pub fn decrypt(encrypted: &[u8], key: &[u8], nonce: Nonce) -> Vec<u8> {
    let key = RandomizedNonceKey::new(&AES_256_GCM, key).unwrap();
    let mut in_out: Vec<u8> = Vec::from(encrypted);

    key.open_in_place(nonce, Aad::empty(), &mut in_out).unwrap();
    in_out.truncate(in_out.len() - TAG_LEN);
    in_out
}

#[test]
fn crypt_integrity() {
    let pass = "password";
    let data = "random";
    let (key, _) = derive_aes_key(pass, None);
    let (encrypted, nonce) = encrypt(data.as_bytes(), &key);
    let decrypted = decrypt(&encrypted, &key, nonce);
    assert_eq!(data, String::from_utf8_lossy(&decrypted));
}
