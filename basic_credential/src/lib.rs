//! # Basic Credential
//!
//! An implementation of the basic credential from the MLS spec.
//!
//! For now this credential uses only RustCrypto.

use std::fmt::Debug;

use openmls_traits::{
    signatures::{Signer, SignerError},
    storage::{self, StorageProvider, CURRENT_VERSION},
    types::{CryptoError, SignatureScheme},
};

use ml_dsa::{
    signature::{Signer as MlDsaSigner, Verifier as MlDsaVerifier},
    EncodedSignature as MlDsaEncodedSignature, EncodedSigningKey as MlDsaEncodedSigningKey,
    EncodedVerifyingKey as MlDsaEncodedVerifyingKey, KeyGen, MlDsa44, MlDsa65, MlDsa87,
    MlDsaParams, Signature as MlDsaSignature, SigningKey as MlDsaSigningKey,
    VerifyingKey as MlDsaVerifyingKey,
};
use p256::ecdsa::{signature::Signer as P256Signer, Signature, SigningKey};
use slh_dsa::{
    signature::{Keypair as SlhDsaKeypair, Signer as SlhDsaSigner, Verifier as SlhDsaVerifier},
    ParameterSet, Shake128f, Shake128s, Shake192f, Signature as SlhDsaSignature,
    SigningKey as SlhDsaSigningKey, VerifyingKey as SlhDsaVerifyingKey,
};

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

// Parameterized MLDSA functions
fn ml_dsa_key_gen<P: MlDsaParams>(rng: &mut OsRng) -> (Vec<u8>, Vec<u8>) {
    let kp = P::key_gen(rng);
    let sk_bytes = kp.signing_key().encode();
    let pk_bytes = kp.verifying_key().encode();
    (sk_bytes.as_slice().to_vec(), pk_bytes.as_slice().to_vec())
}

fn ml_dsa_sign<P: MlDsaParams>(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sk_bytes =
        MlDsaEncodedSigningKey::<P>::try_from(key).expect("Failed to decode MLDSA signing key");
    let sk = MlDsaSigningKey::<P>::decode(&sk_bytes);
    let signature = sk.sign(data);
    let signature_bytes = signature.encode();
    let signature_vec = signature_bytes.as_slice().to_vec();
    Ok(signature_vec)
}

// Parameterized SLHDSA functions
fn slh_dsa_key_gen<P: ParameterSet>(rng: &mut OsRng) -> (Vec<u8>, Vec<u8>) {
    let sk = SlhDsaSigningKey::<P>::new(rng);
    let pk = sk.verifying_key();
    let sk_vec = sk.to_vec();
    let pk_vec = pk.to_vec();
    (sk_vec, pk_vec)
}

fn slh_dsa_sign<P: ParameterSet>(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sk_deserialized =
        SlhDsaSigningKey::<P>::try_from(key).expect("Failed to decode SLHDSA signing key");
    let signature = sk_deserialized.sign(data);
    let signature_vec = signature.to_vec();
    Ok(signature_vec)
}

/// A signature key pair for the basic credential.
///
/// This can be used as keys to implement the MLS basic credential. It is a simple
/// private and public key pair with corresponding signature scheme.
#[derive(
    TlsSerialize, TlsSize, TlsDeserialize, TlsDeserializeBytes, serde::Serialize, serde::Deserialize,
)]
#[cfg_attr(feature = "clonable", derive(Clone))]
pub struct SignatureKeyPair {
    private: Vec<u8>,
    public: Vec<u8>,
    signature_scheme: SignatureScheme,
}

impl Debug for SignatureKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureKeyPair")
            .field("private", &"***".to_string())
            .field("public", &self.public)
            .field("signature_scheme", &self.signature_scheme)
            .finish()
    }
}

impl Signer for SignatureKeyPair {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        match self.signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = SigningKey::from_bytes(self.private.as_slice().into())
                    .map_err(|_| SignerError::SigningError)?;
                let signature: Signature = k.sign(payload);
                Ok(signature.to_der().to_bytes().into())
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::SigningKey::try_from(self.private.as_slice())
                    .map_err(|_| SignerError::SigningError)?;
                let signature = k.sign(payload);
                Ok(signature.to_bytes().into())
            }
            SignatureScheme::MLDSA44 => {
                let signature = ml_dsa_sign::<MlDsa44>(payload, self.private.as_slice())
                    .map_err(|_| SignerError::SigningError)?;
                Ok(signature)
            }
            SignatureScheme::MLDSA65 => {
                let signature = ml_dsa_sign::<MlDsa65>(payload, self.private.as_slice())
                    .map_err(|_| SignerError::SigningError)?;
                Ok(signature)
            }
            SignatureScheme::MLDSA87 => {
                let signature = ml_dsa_sign::<MlDsa87>(payload, self.private.as_slice())
                    .map_err(|_| SignerError::SigningError)?;
                Ok(signature)
            }
            SignatureScheme::SLHDSA_SHA2_128F => {
                let signature = slh_dsa_sign::<Shake128f>(payload, self.private.as_slice())
                    .map_err(|_| SignerError::SigningError)?;
                Ok(signature)
            }
            _ => Err(SignerError::SigningError),
        }
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }
}

/// Compute the ID for a [`Signature`] in the key store.
fn id(public_key: &[u8], signature_scheme: SignatureScheme) -> Vec<u8> {
    const LABEL: &[u8; 22] = b"RustCryptoSignatureKey";
    let mut id = public_key.to_vec();
    id.extend_from_slice(LABEL);
    let signature_scheme = (signature_scheme as u16).to_be_bytes();
    id.extend_from_slice(&signature_scheme);
    id
}

impl SignatureKeyPair {
    /// Generates a fresh signature keypair using the [`SignatureScheme`].
    pub fn new(signature_scheme: SignatureScheme) -> Result<Self, CryptoError> {
        let (private, public) = match signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = SigningKey::random(&mut OsRng);
                let pk = k.verifying_key().to_encoded_point(false).as_bytes().into();
                (k.to_bytes().as_slice().into(), pk)
            }
            SignatureScheme::ED25519 => {
                let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
                let pk = sk.verifying_key().to_bytes().into();
                (sk.to_bytes().into(), pk)
            }
            SignatureScheme::MLDSA44 => {
                let (private, public) = ml_dsa_key_gen::<MlDsa44>(&mut OsRng);
                (private, public)
            }
            SignatureScheme::MLDSA65 => {
                let (private, public) = ml_dsa_key_gen::<MlDsa65>(&mut OsRng);
                (private, public)
            }
            SignatureScheme::MLDSA87 => {
                let (private, public) = ml_dsa_key_gen::<MlDsa87>(&mut OsRng);
                (private, public)
            }
            SignatureScheme::SLHDSA_SHA2_128F => {
                let (private, public) = slh_dsa_key_gen::<Shake128f>(&mut OsRng);
                (private, public)
            }
            _ => return Err(CryptoError::UnsupportedSignatureScheme),
        };

        Ok(Self {
            private,
            public,
            signature_scheme,
        })
    }

    /// Create a new signature key pair from the raw keys.
    pub fn from_raw(signature_scheme: SignatureScheme, private: Vec<u8>, public: Vec<u8>) -> Self {
        Self {
            private,
            public,
            signature_scheme,
        }
    }

    pub fn id(&self) -> StorageId {
        StorageId {
            value: id(&self.public, self.signature_scheme),
        }
    }

    /// Store this signature key pair in the key store.
    pub fn store<T>(&self, store: &T) -> Result<(), T::Error>
    where
        T: StorageProvider<CURRENT_VERSION>,
    {
        store.write_signature_key_pair(&self.id(), self)
    }

    /// Read a signature key pair from the key store.
    pub fn read(
        store: &impl StorageProvider<CURRENT_VERSION>,
        public_key: &[u8],
        signature_scheme: SignatureScheme,
    ) -> Option<Self> {
        store
            .signature_key_pair(&StorageId {
                value: id(public_key, signature_scheme),
            })
            .ok()
            .flatten()
    }

    /// Delete a signature key pair from the key store.
    pub fn delete<T: StorageProvider<CURRENT_VERSION>>(
        store: &T,
        public_key: &[u8],
        signature_scheme: SignatureScheme,
    ) -> Result<(), T::Error> {
        let id = StorageId {
            value: id(public_key, signature_scheme),
        };
        store.delete_signature_key_pair(&id)
    }

    /// Get the public key as byte slice.
    pub fn public(&self) -> &[u8] {
        self.public.as_ref()
    }

    /// Get the public key as byte vector.
    pub fn to_public_vec(&self) -> Vec<u8> {
        self.public.clone()
    }

    /// Get the [`SignatureScheme`] of this signature key.
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }

    #[cfg(feature = "test-utils")]
    pub fn private(&self) -> &[u8] {
        &self.private
    }
}

// Storage

#[derive(Debug, Serialize, Deserialize)]
pub struct StorageId {
    value: Vec<u8>,
}

impl From<Vec<u8>> for StorageId {
    fn from(vec: Vec<u8>) -> Self {
        StorageId { value: vec }
    }
}

// Implement key traits for the storage id
impl storage::Key<CURRENT_VERSION> for StorageId {}
impl storage::traits::SignaturePublicKey<CURRENT_VERSION> for StorageId {}

// Implement entity trait for the signature key pair
impl storage::Entity<CURRENT_VERSION> for SignatureKeyPair {}
impl storage::traits::SignatureKeyPair<CURRENT_VERSION> for SignatureKeyPair {}
