use super::*;
use curve25519_dalek::{
    constants::{BASEPOINT_ORDER, X25519_BASEPOINT},
    montgomery::MontgomeryPoint,
    scalar::Scalar,
};
use ring::constant_time::verify_slices_are_equal;
use ring::rand::SecureRandom;

#[derive(Clone, Debug)]
pub struct X25519PublicKey {
    alg: KxAlgorithm,
    group_element: MontgomeryPoint,
}

#[derive(Clone, Debug)]
pub struct X25519SecretKey {
    alg: KxAlgorithm,
    raw: Vec<u8>,
    clamped_scalar: Scalar,
}

impl X25519SecretKey {
    fn new(alg: KxAlgorithm, raw: Vec<u8>) -> Self {
        let mut sk_clamped = [0u8; 32];
        sk_clamped.copy_from_slice(&raw);
        sk_clamped[0] &= 248;
        sk_clamped[31] |= 64;
        let clamped_scalar = Scalar::from_bits(sk_clamped);
        X25519SecretKey {
            alg,
            raw,
            clamped_scalar,
        }
    }
}

#[derive(Clone, Debug)]
pub struct X25519KeyPair {
    alg: KxAlgorithm,
    pk: X25519PublicKey,
    sk: X25519SecretKey,
}

pub struct X25519KeyPairBuilder {
    alg: KxAlgorithm,
}

impl X25519KeyPairBuilder {
    pub fn new(alg: KxAlgorithm) -> Box<dyn KxKeyPairBuilder> {
        Box::new(Self { alg })
    }
}

fn reject_neutral_element(pk: &MontgomeryPoint) -> Result<(), CryptoError> {
    let zero = [0u8; 32];
    let mut pk_ = [0u8; 32];
    pk_.copy_from_slice(&pk.0);
    pk_[31] &= 127;
    verify_slices_are_equal(&zero, &pk_).map_err(|_| CryptoError::InvalidKey)?;
    Ok(())
}

static L: [u8; 32] = [
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
];

fn reject_noncanonical_fe(s: &[u8]) -> Result<(), CryptoError> {
    let mut c: u8 = 0;
    let mut n: u8 = 1;

    let mut i = 31;
    loop {
        c |= ((((s[i] as i32) - (L[i] as i32)) >> 8) as u8) & n;
        n &= ((((s[i] ^ L[i]) as i32) - 1) >> 8) as u8;
        if i == 0 {
            break;
        } else {
            i -= 1;
        }
    }
    if c == 0 {
        Ok(())
    } else {
        bail!(CryptoError::InvalidKey)
    }
}

impl KxKeyPairBuilder for X25519KeyPairBuilder {
    fn generate(&self, _options: Option<KxOptions>) -> Result<KxKeyPair, CryptoError> {
        let rng = ring::rand::SystemRandom::new();
        let mut sk_raw = vec![0u8; 32];
        rng.fill(&mut sk_raw).map_err(|_| CryptoError::RNGError)?;
        let sk = X25519SecretKey::new(self.alg, sk_raw);
        let pk = sk.into_x25519_publickey()?;
        let kp = X25519KeyPair {
            alg: self.alg,
            pk,
            sk,
        };
        Ok(KxKeyPair::new(Box::new(kp)))
    }
}

pub struct X25519SecretKeyBuilder {
    alg: KxAlgorithm,
}

impl KxSecretKeyBuilder for X25519SecretKeyBuilder {
    fn from_raw(&self, raw: &[u8]) -> Result<KxSecretKey, CryptoError> {
        ensure!(raw.len() == 32, CryptoError::InvalidKey);
        let sk = X25519SecretKey::new(self.alg, raw.to_vec());
        Ok(KxSecretKey::new(Box::new(sk)))
    }
}

impl X25519SecretKeyBuilder {
    pub fn new(alg: KxAlgorithm) -> Box<dyn KxSecretKeyBuilder> {
        Box::new(Self { alg })
    }
}

impl KxKeyPairLike for X25519KeyPair {
    fn alg(&self) -> KxAlgorithm {
        self.alg
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl KxPublicKeyLike for X25519PublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn alg(&self) -> KxAlgorithm {
        self.alg
    }

    fn as_raw(&self) -> Result<&[u8], CryptoError> {
        Ok(self.group_element.as_bytes())
    }

    fn verify(&self) -> Result<(), CryptoError> {
        reject_neutral_element(&self.group_element)?;
        reject_noncanonical_fe(&self.group_element.0)?;
        let order_check = BASEPOINT_ORDER * self.group_element;
        ensure!(
            reject_neutral_element(&order_check).is_err(),
            CryptoError::InvalidKey
        );
        Ok(())
    }
}

impl X25519SecretKey {
    fn into_x25519_publickey(&self) -> Result<X25519PublicKey, CryptoError> {
        let group_element = X25519_BASEPOINT * self.clamped_scalar;
        reject_neutral_element(&group_element).map_err(|_| CryptoError::RNGError)?;
        let pk = X25519PublicKey {
            alg: self.alg,
            group_element,
        };
        Ok(pk)
    }
}

impl KxSecretKeyLike for X25519SecretKey {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn alg(&self) -> KxAlgorithm {
        self.alg
    }

    fn as_raw(&self) -> Result<&[u8], CryptoError> {
        Ok(&self.raw)
    }

    fn into_publickey(&self) -> Result<KxPublicKey, CryptoError> {
        Ok(KxPublicKey::new(Box::new(self.into_x25519_publickey()?)))
    }
}
