use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;

/// A public key
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey(pub(crate) RistrettoPoint);

impl PublicKey {
    /// Serialize this public key to 32 bytes
    pub fn as_bytes(&self) -> Vec<u8> {
        let c = self.0.compress();
        c.as_bytes().to_vec()
    }

    // TODO: Make this more robust
    /// Deserialize this public key from 32 bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<PublicKey> {
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        let c = CompressedRistretto(arr);
        c.decompress().map(|p| PublicKey(p))
    }
}

/// A private key
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateKey(pub(crate) Scalar, pub(crate) RistrettoPoint);

impl PrivateKey {
    /// Serialize this private key to 64 bytes
    pub fn as_bytes(&self) -> Vec<u8> {
        let privkey_bytes = self.0.as_bytes().to_vec();
        let pubkey_bytes = {
            let p = PublicKey(self.1.clone());
            p.as_bytes()
        };

        [privkey_bytes, pubkey_bytes].concat()
    }

    // TODO: Make more robust
    /// Deserialize this private key from 64 bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<PrivateKey> {
        if bytes.len() != 64 {
            return None;
        }
        let (scalar_bytes, pubkey_point_bytes) = bytes.split_at(32);

        let scalar = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(scalar_bytes);
            Scalar::from_bits(arr)
        };
        let pubkey_point = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(pubkey_point_bytes);
            let c = CompressedRistretto(arr);
            c.decompress()
        };

        pubkey_point.map(|p| PrivateKey(scalar, p))
    }
}

/// A private and public keypair
#[derive(Clone)]
pub struct KeyPair {
    pub pubkey: PublicKey,
    pub privkey: PrivateKey,
}

impl KeyPair {
    /// Generate a secure random keypair
    pub fn generate() -> KeyPair {
        let mut csprng = OsRng;
        let s = Scalar::random(&mut csprng);
        let pubkey = PublicKey(&s * &RISTRETTO_BASEPOINT_POINT);
        let privkey = PrivateKey(s, pubkey.0.clone());

        KeyPair { pubkey, privkey }
    }

    pub fn generate_from_bits(bytes: [u8; 32]) -> KeyPair {
        let s = Scalar::from_bits(bytes);
        let pubkey = PublicKey(&s * &RISTRETTO_BASEPOINT_POINT);
        let privkey = PrivateKey(s, pubkey.0.clone());

        KeyPair { pubkey, privkey }
    }
}

#[cfg(test)]
mod test {
    use super::{KeyPair, PrivateKey, PublicKey};

    #[test]
    fn test_key_serialization_correctness() {
        let KeyPair { pubkey, privkey } = KeyPair::generate();

        let pubkey_bytes = pubkey.as_bytes();
        assert_eq!(PublicKey::from_bytes(&*pubkey_bytes), Some(pubkey));

        let privkey_bytes = privkey.as_bytes();
        assert_eq!(PrivateKey::from_bytes(&*privkey_bytes), Some(privkey));
    }

    #[test]
    fn test_key_serialization_robustness() {
        // 31 bytes should be too short for anything
        let bytes = [1u8; 31];
        assert_eq!(PublicKey::from_bytes(&bytes), None);
        assert_eq!(PrivateKey::from_bytes(&bytes), None);
    }

    #[test]
    fn test_generate_from_bits() {
        let bytes = [0x42; 32];
        let kp1 = KeyPair::generate_from_bits(bytes);
        let kp2 = KeyPair::generate_from_bits(bytes);

        // Should have generated the same keypair given the same seed.
        assert_eq!(kp1.pubkey, kp2.pubkey);
        assert_eq!(kp1.privkey, kp2.privkey);

        let bytes2 = [0x43; 32];
        let kp3 = KeyPair::generate_from_bits(bytes2);
        // Different seed should produce different keypair:
        assert_ne!(kp3.pubkey, kp1.pubkey);
        assert_ne!(kp3.privkey, kp1.privkey);
    }
}
