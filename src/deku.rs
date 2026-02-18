use std::path::Path;

use aws_lc_rs::aead::Nonce;
use deku::prelude::*;
use ml_kem::{
    Decapsulate, Encapsulate, Key, Seed,
    ml_kem_1024::{Ciphertext, DecapsulationKey, EncapsulationKey},
};

use crate::{
    aes::{decrypt, encrypt},
    argon2::derive_aes_key,
    io::{read_file, write_file},
    kem::{bytes_to_encap, seed_bytes},
};

const PUB_KEY_SIZE: usize = 1568;

#[derive(DekuRead, DekuWrite, DekuSize)]
#[deku(id_type = "u8")]
pub enum PublicKey {
    #[deku(id = "0")]
    Ciphertext([u8; PUB_KEY_SIZE]),
    #[deku(id = "1")]
    EncapsulationKey([u8; PUB_KEY_SIZE]),
}
impl PublicKey {
    pub fn new_ciphertext(bytes: Vec<u8>) -> Self {
        assert_eq!(bytes.len(), PUB_KEY_SIZE);
        PublicKey::Ciphertext(bytes.try_into().unwrap())
    }
    pub fn new_encapsulation_key(bytes: Vec<u8>) -> Self {
        assert_eq!(bytes.len(), PUB_KEY_SIZE);
        PublicKey::EncapsulationKey(bytes.try_into().unwrap())
    }
    /// Converts an encapsulation key into a ciphertext key.
    ///
    /// This does nothing and returns itself if it is already a ciphertext key.
    pub fn into_ciphertext(self) -> Self {
        match self {
            PublicKey::Ciphertext(_) => self,
            PublicKey::EncapsulationKey(bytes) => {
                let (ciphertext, _) = bytes_to_encap(bytes.to_vec()).encapsulate();
                PublicKey::Ciphertext(ciphertext.try_into().unwrap())
            }
        }
    }
    pub fn save(&self, path: impl AsRef<Path>) {
        let bytes = self.to_bytes().unwrap();
        write_file(path, &bytes).unwrap();
    }
    pub fn load(path: impl AsRef<Path>) -> Self {
        let bytes = read_file(path).unwrap();
        let (_, public_key) = Self::from_bytes((&bytes, 0)).unwrap();
        public_key
    }
    /*pub fn encrypt(   // Already fulfilled by EncryptedMessage
        &self,
        data: Vec<u8>,
        decap_for_ciphertext: Option<DecapsulationKey>,
    ) -> Vec<u8> {
        let secret = match self {
            PublicKey::Ciphertext(b) => {
                let ct = Ciphertext { 0: *b };
                decap_for_ciphertext.unwrap().decapsulate(&ct)
            }
            PublicKey::EncapsulationKey(b) => {
                let ek = bytes_to_encap(b.to_vec());
                let (_, s) = ek.encapsulate();
                s
            }
        };
        encrypt(&data, &secret)
    }*/
}

#[derive(DekuRead, DekuWrite)]
pub struct EncryptedSeed {
    pub nonce: [u8; 12],
    pub salt: [u8; 16],
    #[deku(read_all)]
    pub seed: Vec<u8>,
}
impl EncryptedSeed {
    pub fn new(password: String, decap: &DecapsulationKey) -> Self {
        let (key, salt) = derive_aes_key(&password, None);
        let seed = seed_bytes(&decap);
        let (encrypted, nonce) = encrypt(&seed, &key);
        Self {
            nonce: *nonce.as_ref(),
            salt,
            seed: encrypted,
        }
    }
    pub fn save(&self, path: impl AsRef<Path>) {
        let encrypted_seed_bytes = self.to_bytes().unwrap();
        write_file(path, &encrypted_seed_bytes).unwrap();
    }
    pub fn load(path: impl AsRef<Path>) -> Self {
        let encrypted_seed_bytes = read_file(path).unwrap();
        let (_, encrypted_seed) = Self::from_bytes((&encrypted_seed_bytes, 0)).unwrap();
        encrypted_seed
    }
    pub fn decrypt(&self, password: String) -> DecapsulationKey {
        let (key, _) = derive_aes_key(&password, Some(self.salt));
        let nonce = Nonce::assume_unique_for_key(self.nonce);

        let seed_bytes = decrypt(&self.seed, &key, nonce);
        assert_eq!(seed_bytes.len(), 64);
        let seed = Seed {
            0: seed_bytes.try_into().unwrap(),
        };
        DecapsulationKey::from_seed(seed)
    }
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
pub enum EncryptedMessage {
    // Maps to 0: No ciphertext included
    #[deku(id = "0")]
    KeyStored {
        nonce: [u8; 12],
        #[deku(read_all)]
        message: Vec<u8>,
    },

    // Maps to 1: Ciphertext included
    #[deku(id = "1")]
    KeyEncapsulated {
        nonce: [u8; 12],
        ciphertext: [u8; PUB_KEY_SIZE],
        #[deku(read_all)]
        message: Vec<u8>,
    },
}
impl EncryptedMessage {
    pub fn with_ciphertext(
        message: String,
        decap: DecapsulationKey,
        ciphertext: Ciphertext,
    ) -> Self {
        let secret = decap.decapsulate(&ciphertext);
        let (message, nonce) = encrypt(message.as_bytes(), &secret);
        Self::KeyStored {
            nonce: *nonce.as_ref(),
            message,
        }
    }
    pub fn with_encapsulationkey(message: String, encap: EncapsulationKey) -> Self {
        let (ciphertext, secret) = encap.encapsulate();
        let (message, nonce) = encrypt(message.as_bytes(), &secret);
        Self::KeyEncapsulated {
            nonce: *nonce.as_ref(),
            ciphertext: ciphertext.try_into().unwrap(),
            message,
        }
    }
}
