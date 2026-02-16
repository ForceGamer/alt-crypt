use ml_kem::{
    Encapsulate, Kem, Key, KeyExport, MlKem1024, Seed,
    ml_kem_1024::{DecapsulationKey, EncapsulationKey},
};

const ENCAP_LEN: usize = 1568;
const SEED_LEN: usize = 64;
const CIPHER_LEN: usize = 1568;

/*enum BytesIdentity {
    Encap([u8; ENCAP_LEN]),
    Seed([u8; SEED_LEN]),
    Ciphertext,
    Nonce,
    Salt,
    Unknown(Vec<u8>),
}

pub fn identify_bytes(bytes: Vec<u8>) -> BytesIdentity {
    match bytes.len() {
        ENCAP_LEN => BytesIdentity::Encap(bytes.try_into().unwrap()),
        SEED_LEN => BytesIdentity::Seed(bytes.try_into().unwrap()),
        _ => BytesIdentity::Unknown(bytes),
    }
}
*/

pub fn generate_keys() {
    let (decap, encap) = MlKem1024::generate_keypair();
}

pub fn seed_bytes(decap: DecapsulationKey) -> Vec<u8> {
    decap.to_seed().unwrap().to_vec()
}

pub fn bytes_to_seed(bytes: Vec<u8>) -> DecapsulationKey {
    assert_eq!(bytes.len(), SEED_LEN);
    let seed = Seed {
        0: bytes.try_into().unwrap(),
    };
    DecapsulationKey::from_seed(seed)
}

pub fn encap_bytes(encap: EncapsulationKey) -> Vec<u8> {
    encap.to_bytes().0.to_vec()
}

pub fn bytes_to_encap(bytes: Vec<u8>) -> EncapsulationKey {
    assert_eq!(bytes.len(), ENCAP_LEN);
    let key_array: [u8; ENCAP_LEN] = bytes
        .try_into()
        .expect("bytes vector must have exactly 1568 elements");
    let key = Key::<EncapsulationKey> { 0: key_array };
    EncapsulationKey::new(&key).unwrap()
}

#[test]
fn test_encap_encoding() {
    let (_, encap) = MlKem1024::generate_keypair();
    let bytes = encap_bytes(encap.clone());
    let restored = bytes_to_encap(bytes);
    assert_eq!(encap, restored);
}

#[test]
fn test_decap_encoding() {
    let (decap, _) = MlKem1024::generate_keypair();
    let bytes = seed_bytes(decap.clone());
    let restored = bytes_to_seed(bytes);
    assert_eq!(decap, restored);
}
