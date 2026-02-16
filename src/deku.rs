use deku::prelude::*;

#[derive(DekuRead, DekuWrite, DekuSize)]
#[deku(id_type = "u8", endian = "big")]
pub enum PublicKey {
    #[deku(id = "1")]
    Ciphertext([u8; 1568]),
    #[deku(id = "2")]
    EncapsulationKey([u8; 1568]),
}

#[derive(DekuRead, DekuWrite)]
pub struct EncryptedSeed {
    nonce: [u8; 12],
    salt: [u8; 16],
    #[deku(update = "self.seed.len()")]
    seed_len: u16,
    #[deku(count = "seed_len")]
    seed: Vec<u8>,
}
