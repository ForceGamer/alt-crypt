use deku::prelude::*;
use ml_kem::{
    Decapsulate, Encapsulate, InvalidKey, Key, KeyExport, Seed,
    ml_kem_1024::{
        Ciphertext as CiphertextPrimitive, DecapsulationKey as DecapPrimitive,
        EncapsulationKey as EncapPrimitive,
    },
};

#[derive(DekuRead, DekuWrite, Clone, PartialEq, Debug)]
#[deku(endian = "big")]
pub struct EncapsulationKey(pub [u8; 1568]);

#[derive(DekuRead, DekuWrite, Clone, PartialEq, Debug)]
#[deku(endian = "big")]
pub struct DecapsulationKey(pub [u8; 64]);

pub type Ciphertext = [u8; 1568];
pub type Secret = [u8; 32];

#[derive(DekuRead, DekuWrite, Clone, PartialEq, Debug)]
#[deku(endian = "big")]
pub struct EncryptedPayload {
    pub nonce: [u8; 12],
    #[deku(read_all)]
    pub ciphertext: Vec<u8>,
}

#[derive(DekuRead, DekuWrite, Clone, PartialEq, Debug)]
#[deku(endian = "big")]
pub struct PasswordProtectedData {
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    #[deku(read_all)]
    pub ciphertext: Vec<u8>,
}

#[derive(DekuRead, DekuWrite, Clone, PartialEq, Debug)]
#[deku(id_type = "u8")]
pub enum KeyUpdateBundle {
    #[deku(id = "0x00")]
    None,
    #[deku(id = "0x01")]
    Offer(EncapsulationKey),
    #[deku(id = "0x02")]
    Response(Ciphertext),
}

#[derive(DekuRead, DekuWrite, Clone, PartialEq, Debug)]
pub struct RatchetPayload {
    pub content: EncryptedPayload,
    pub key_update: KeyUpdateBundle,
}

/// Friend Request initiating the handshake.
#[derive(DekuRead, DekuWrite, Clone, PartialEq, Debug)]
pub struct FriendRequest {
    pub encapsulation_key: EncapsulationKey,
}

/// Friend Acceptance completing the handshake.
#[derive(DekuRead, DekuWrite, Clone, PartialEq, Debug)]
#[deku(endian = "big")]
pub struct FriendAccept {
    pub kem_ciphertext: Ciphertext,
}

#[derive(DekuRead, DekuWrite, Clone, PartialEq, Debug)]
#[deku(id_type = "u8")]
pub enum PendingKeyExchange {
    #[deku(id = "0x00")]
    OutgoingOffer {
        decapsulation_key: PasswordProtectedData,
    },
    #[deku(id = "0x01")]
    IncomingOffer { encapsulation_key: EncapsulationKey },
}

/// Persistent session state stored on disk.
#[derive(DekuRead, DekuWrite, Clone, PartialEq, Debug)]
pub struct StoredSession {
    pub current_secret: PasswordProtectedData,
    pub pending_exchange: Option<PendingKeyExchange>,
}

impl EncapsulationKey {
    pub fn new(primitive: EncapPrimitive) -> Self {
        Self(primitive.to_bytes().0)
    }
    pub fn into_primitive(&self) -> Result<EncapPrimitive, InvalidKey> {
        let key = Key::<EncapPrimitive> { 0: self.0 };
        EncapPrimitive::new(&key)
    }
    pub fn encapsulate(&self) -> Result<(Ciphertext, Secret), InvalidKey> {
        let primitive = self.into_primitive()?;
        let (ct, ss) = primitive.encapsulate();
        Ok((ct.0, ss.0))
    }
}

impl DecapsulationKey {
    pub fn new(primitive: DecapPrimitive) -> Result<Self, String> {
        let seed = primitive.to_seed().ok_or_else(|| "Failed to derive seed")?;
        Ok(Self(seed.0))
    }
    pub fn into_primitive(&self) -> DecapPrimitive {
        let seed = Seed { 0: self.0 };
        DecapPrimitive::from_seed(seed)
    }
    pub fn decapsulate(&self, ciphertext: [u8; 1568]) -> Secret {
        let ct = CiphertextPrimitive { 0: ciphertext };
        let primitive = self.into_primitive();
        primitive.decapsulate(&ct).0
    }
}
