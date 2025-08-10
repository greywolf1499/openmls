//! # OpenMLS Types
//!
//! This module holds a number of types that are needed by the traits.

use std::ops::Deref;

use serde::{Deserialize, Serialize};
use tls_codec::{
    SecretVLBytes, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes,
};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
#[repr(u16)]
/// AEAD types
pub enum AeadType {
    /// AES GCM 128
    Aes128Gcm = 0x0001,

    /// AES GCM 256
    Aes256Gcm = 0x0002,

    /// ChaCha20 Poly1305
    ChaCha20Poly1305 = 0x0003,
}

impl AeadType {
    /// Get the tag size of the [`AeadType`] in bytes.
    pub const fn tag_size(&self) -> usize {
        match self {
            AeadType::Aes128Gcm => 16,
            AeadType::Aes256Gcm => 16,
            AeadType::ChaCha20Poly1305 => 16,
        }
    }

    /// Get the key size of the [`AeadType`] in bytes.
    pub const fn key_size(&self) -> usize {
        match self {
            AeadType::Aes128Gcm => 16,
            AeadType::Aes256Gcm => 32,
            AeadType::ChaCha20Poly1305 => 32,
        }
    }

    /// Get the nonce size of the [`AeadType`] in bytes.
    pub const fn nonce_size(&self) -> usize {
        match self {
            AeadType::Aes128Gcm | AeadType::Aes256Gcm | AeadType::ChaCha20Poly1305 => 12,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
#[allow(non_camel_case_types)]
/// Hash types
pub enum HashType {
    Sha2_256 = 0x04,
    Sha2_384 = 0x05,
    Sha2_512 = 0x06,
}

impl HashType {
    /// Returns the output size of a hash by [`HashType`].
    #[inline]
    pub const fn size(&self) -> usize {
        match self {
            HashType::Sha2_256 => 32,
            HashType::Sha2_384 => 48,
            HashType::Sha2_512 => 64,
        }
    }
}

/// SignatureScheme according to IANA TLS parameters
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(
    Copy,
    Hash,
    Eq,
    PartialEq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
#[repr(u16)]
pub enum SignatureScheme {
    /// ECDSA_SECP256R1_SHA256
    ECDSA_SECP256R1_SHA256 = 0x0403,
    /// ECDSA_SECP384R1_SHA384
    ECDSA_SECP384R1_SHA384 = 0x0503,
    /// ECDSA_SECP521R1_SHA512
    ECDSA_SECP521R1_SHA512 = 0x0603,
    /// ED25519
    ED25519 = 0x0807,
    /// ED448
    ED448 = 0x0808,
    // ML-DSA
    MLDSA44 = 0x0809,
    MLDSA65 = 0x080A,
    MLDSA87 = 0x080B,
    // SLH-DSA
    SLHDSA_SHA2_128F = 0x080C,
    SLHDSA_SHA2_128S = 0x080D,
    SLHDSA_SHA2_192F = 0x080E,
    SLHDSA_SHA2_192S = 0x080F,
    SLHDSA_SHA2_256F = 0x0810,
    SLHDSA_SHA2_256S = 0x0811,
    SLHDSA_SHAKE128F = 0x0812,
    SLHDSA_SHAKE128S = 0x0813,
    SLHDSA_SHAKE192F = 0x0814,
    SLHDSA_SHAKE192S = 0x0815,
    SLHDSA_SHAKE256F = 0x0816,
    SLHDSA_SHAKE256S = 0x0817,
    // SPHINCS+
    SPHINCS_SHA2_128F = 0x0818,
    SPHINCS_SHA2_128S = 0x0819,
    SPHINCS_SHA2_192F = 0x081A,
    SPHINCS_SHA2_192S = 0x081B,
    SPHINCS_SHA2_256F = 0x081C,
    SPHINCS_SHA2_256S = 0x081D,
    SPHINCS_SHAKE128F = 0x081E,
    SPHINCS_SHAKE128S = 0x081F,
    SPHINCS_SHAKE192F = 0x0820,
    SPHINCS_SHAKE192S = 0x0821,
    SPHINCS_SHAKE256F = 0x0822,
    SPHINCS_SHAKE256S = 0x0823,
    // FALCON
    FALCON_512 = 0x0824,
    FALCON_1024 = 0x0825,
}

impl TryFrom<u16> for SignatureScheme {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0403 => Ok(SignatureScheme::ECDSA_SECP256R1_SHA256),
            0x0503 => Ok(SignatureScheme::ECDSA_SECP384R1_SHA384),
            0x0603 => Ok(SignatureScheme::ECDSA_SECP521R1_SHA512),
            0x0807 => Ok(SignatureScheme::ED25519),
            0x0808 => Ok(SignatureScheme::ED448),
            0x0809 => Ok(SignatureScheme::MLDSA44),
            0x080A => Ok(SignatureScheme::MLDSA65),
            0x080B => Ok(SignatureScheme::MLDSA87),
            0x080C => Ok(SignatureScheme::SLHDSA_SHA2_128F),
            0x080D => Ok(SignatureScheme::SLHDSA_SHA2_128S),
            0x080E => Ok(SignatureScheme::SLHDSA_SHA2_192F),
            0x080F => Ok(SignatureScheme::SLHDSA_SHA2_192S),
            0x0810 => Ok(SignatureScheme::SLHDSA_SHA2_256F),
            0x0811 => Ok(SignatureScheme::SLHDSA_SHA2_256S),
            0x0812 => Ok(SignatureScheme::SLHDSA_SHAKE128F),
            0x0813 => Ok(SignatureScheme::SLHDSA_SHAKE128S),
            0x0814 => Ok(SignatureScheme::SLHDSA_SHAKE192F),
            0x0815 => Ok(SignatureScheme::SLHDSA_SHAKE192S),
            0x0816 => Ok(SignatureScheme::SLHDSA_SHAKE256F),
            0x0817 => Ok(SignatureScheme::SLHDSA_SHAKE256S),
            0x0818 => Ok(SignatureScheme::SPHINCS_SHA2_128F),
            0x0819 => Ok(SignatureScheme::SPHINCS_SHA2_128S),
            0x081A => Ok(SignatureScheme::SPHINCS_SHA2_192F),
            0x081B => Ok(SignatureScheme::SPHINCS_SHA2_192S),
            0x081C => Ok(SignatureScheme::SPHINCS_SHA2_256F),
            0x081D => Ok(SignatureScheme::SPHINCS_SHA2_256S),
            0x081E => Ok(SignatureScheme::SPHINCS_SHAKE128F),
            0x081F => Ok(SignatureScheme::SPHINCS_SHAKE128S),
            0x0820 => Ok(SignatureScheme::SPHINCS_SHAKE192F),
            0x0821 => Ok(SignatureScheme::SPHINCS_SHAKE192S),
            0x0822 => Ok(SignatureScheme::SPHINCS_SHAKE256F),
            0x0823 => Ok(SignatureScheme::SPHINCS_SHAKE256S),
            0x0824 => Ok(SignatureScheme::FALCON_512),
            0x0825 => Ok(SignatureScheme::FALCON_1024),
            _ => Err(format!("Unsupported SignatureScheme: {value}")),
        }
    }
}

/// Crypto errors.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CryptoError {
    CryptoLibraryError,
    AeadDecryptionError,
    HpkeDecryptionError,
    HpkeEncryptionError,
    UnsupportedSignatureScheme,
    KdfLabelTooLarge,
    KdfSerializationError,
    HkdfOutputLengthInvalid,
    InsufficientRandomness,
    InvalidSignature,
    UnsupportedAeadAlgorithm,
    UnsupportedKdf,
    InvalidLength,
    UnsupportedHashAlgorithm,
    SignatureEncodingError,
    SignatureDecodingError,
    SenderSetupError,
    ReceiverSetupError,
    ExporterError,
    UnsupportedCiphersuite,
    TlsSerializationError,
    TooMuchData,
    SigningError,
    InvalidPublicKey,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CryptoError {}

// === HPKE === //

/// Convenience tuple struct for an HPKE configuration.
#[derive(Debug)]
pub struct HpkeConfig(pub HpkeKemType, pub HpkeKdfType, pub HpkeAeadType);

/// KEM Types for HPKE
#[derive(PartialEq, Eq, Copy, Clone, Debug, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeKemType {
    /// DH KEM on P256
    DhKemP256 = 0x0010,

    /// DH KEM on P384
    DhKemP384 = 0x0011,

    /// DH KEM on P521
    DhKemP521 = 0x0012,

    /// DH KEM on x25519
    DhKem25519 = 0x0020,

    /// DH KEM on x448
    DhKem448 = 0x0021,

    /// XWing combiner for ML-KEM and X25519
    XWingKemDraft6 = 0x004D,
}

/// KDF Types for HPKE
#[derive(PartialEq, Eq, Copy, Clone, Debug, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeKdfType {
    /// HKDF SHA 256
    HkdfSha256 = 0x0001,

    /// HKDF SHA 384
    HkdfSha384 = 0x0002,

    /// HKDF SHA 512
    HkdfSha512 = 0x0003,
}

/// AEAD Types for HPKE.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeAeadType {
    /// AES GCM 128
    AesGcm128 = 0x0001,

    /// AES GCM 256
    AesGcm256 = 0x0002,

    /// ChaCha20 Poly1305
    ChaCha20Poly1305 = 0x0003,

    /// Export-only
    Export = 0xFFFF,
}

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     opaque kem_output<V>;
///     opaque ciphertext<V>;
/// } HPKECiphertext;
/// ```
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct HpkeCiphertext {
    pub kem_output: VLBytes,
    pub ciphertext: VLBytes,
}

/// A simple type for HPKE private keys.
#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
#[cfg_attr(feature = "test-utils", derive(PartialEq, Eq))]
#[serde(transparent)]
pub struct HpkePrivateKey(SecretVLBytes);

impl From<Vec<u8>> for HpkePrivateKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes.into())
    }
}

impl From<&[u8]> for HpkePrivateKey {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.into())
    }
}

impl std::ops::Deref for HpkePrivateKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

/// Helper holding a (private, public) key pair as byte vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkeKeyPair {
    pub private: HpkePrivateKey,
    pub public: Vec<u8>,
}

pub type KemOutput = Vec<u8>;
#[derive(Clone, Debug)]
pub struct ExporterSecret(SecretVLBytes);

impl Deref for ExporterSecret {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl From<Vec<u8>> for ExporterSecret {
    fn from(secret: Vec<u8>) -> Self {
        Self(secret.into())
    }
}

/// A currently unknown ciphersuite.
///
/// Used to accept unknown values, e.g., in `Capabilities`.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct VerifiableCiphersuite(u16);

impl VerifiableCiphersuite {
    pub fn new(value: u16) -> Self {
        Self(value)
    }
}

impl From<Ciphersuite> for VerifiableCiphersuite {
    fn from(value: Ciphersuite) -> Self {
        Self(value as u16)
    }
}

/// MLS ciphersuites.
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
#[repr(u16)]
pub enum Ciphersuite {
    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | Ed25519
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,

    /// DH KEM P256 | AES-GCM 128 | SHA2-256 | EcDSA P256
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,

    /// DH KEM x25519 | Chacha20Poly1305 | SHA2-256 | Ed25519
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,

    /// DH KEM x448 | AES-GCM 256 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,

    /// DH KEM P521 | AES-GCM 256 | SHA2-512 | EcDSA P521
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,

    /// DH KEM x448 | Chacha20Poly1305 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,

    /// DH KEM P384 | AES-GCM 256 | SHA2-384 | EcDSA P384
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007,

    /// X-WING KEM draft-01 | Chacha20Poly1305 | SHA2-256 | Ed25519
    MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 = 0x004D,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | ML-DSA 44
    MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA44 = 0x005D,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | ML-DSA 65
    MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA65 = 0x005E,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | ML-DSA 87
    MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA87 = 0x005F,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SLH-DSA SHA-128F
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_128F = 0x0060,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SLH-DSA SHA-128S
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_128S = 0x0061,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SLH-DSA SHA-192F
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_192F = 0x0062,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SLH-DSA SHA-192S
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_192S = 0x0063,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SLH-DSA SHA-256F
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_256F = 0x0064,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SLH-DSA SHA-256S
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_256S = 0x0065,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SLH-DSA SHAKE 128F
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_128F = 0x0066,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SLH-DSA SHAKE 128S
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_128S = 0x0067,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SLH-DSA SHAKE 192F
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_192F = 0x0068,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SLH-DSA SHAKE 192S
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_192S = 0x0069,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SLH-DSA SHAKE 256F
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_256F = 0x006A,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SLH-DSA SHAKE 256S
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_256S = 0x006B,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SPHINCS+ SHA 128F
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128F = 0x006C,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SPHINCS+ SHA 128S
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128S = 0x006D,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SPHINCS+ SHA 192F
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192F = 0x006E,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SPHINCS+ SHA 192S
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192S = 0x006F,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SPHINCS+ SHA 256F
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256F = 0x0070,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SPHINCS+ SHA 256S
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256S = 0x0071,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SPHINCS+ SHAKE 128F
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_128F = 0x0072,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SPHINCS+ SHAKE 128S
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_128S = 0x0073,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SPHINCS+ SHAKE 192F
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_192F = 0x0074,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SPHINCS+ SHAKE 192S
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_192S = 0x0075,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SPHINCS+ SHAKE 256F
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_256F = 0x0076,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | SPHINCS+ SHAKE 256S
    MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_256S = 0x0077,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | FALCON 512
    MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_512 = 0x0078,

    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | FALCON 1024
    MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_1024 = 0x0079,
}

impl core::fmt::Display for Ciphersuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<Ciphersuite> for u16 {
    #[inline(always)]
    fn from(s: Ciphersuite) -> u16 {
        s as u16
    }
}

impl From<&Ciphersuite> for u16 {
    #[inline(always)]
    fn from(s: &Ciphersuite) -> u16 {
        *s as u16
    }
}

impl TryFrom<u16> for Ciphersuite {
    type Error = tls_codec::Error;

    #[inline(always)]
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x0001 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
            0x0002 => Ok(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256),
            0x0003 => Ok(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
            0x0004 => Ok(Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448),
            0x0005 => Ok(Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521),
            0x0006 => Ok(Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448),
            0x0007 => Ok(Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384),
            0x004D => Ok(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519),
            0x005D => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA44),
            0x005E => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA65),
            0x005F => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA87),
            0x0060 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_128F),
            0x0061 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_128S),
            0x0062 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_192F),
            0x0063 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_192S),
            0x0064 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_256F),
            0x0065 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_256S),
            0x0066 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_128F),
            0x0067 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_128S),
            0x0068 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_192F),
            0x0069 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_192S),
            0x006A => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_256F),
            0x006B => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_256S),
            0x006C => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128F),
            0x006D => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128S),
            0x006E => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192F),
            0x006F => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192S),
            0x0070 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256F),
            0x0071 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256S),
            0x0072 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_128F),
            0x0073 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_128S),
            0x0074 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_192F),
            0x0075 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_192S),
            0x0076 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_256F),
            0x0077 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_256S),
            0x0078 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_512),
            0x0079 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_1024),
            _ => Err(Self::Error::DecodingError(format!(
                "{v} is not a valid ciphersuite value"
            ))),
        }
    }
}

impl From<Ciphersuite> for SignatureScheme {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.signature_algorithm()
    }
}

impl From<Ciphersuite> for AeadType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.aead_algorithm()
    }
}

impl From<Ciphersuite> for HpkeKemType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.hpke_kem_algorithm()
    }
}

impl From<Ciphersuite> for HpkeAeadType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.hpke_aead_algorithm()
    }
}

impl From<Ciphersuite> for HpkeKdfType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.hpke_kdf_algorithm()
    }
}

impl From<Ciphersuite> for HashType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.hash_algorithm()
    }
}

impl Ciphersuite {
    /// Get the [`HashType`] for this [`Ciphersuite`]
    #[inline]
    pub const fn hash_algorithm(&self) -> HashType {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA44
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA65
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA87
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_512
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_1024 => HashType::Sha2_256,
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => HashType::Sha2_384,
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => HashType::Sha2_512,
        }
    }

    /// Get the [`SignatureScheme`] for this [`Ciphersuite`].
    #[inline]
    pub const fn signature_algorithm(&self) -> SignatureScheme {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                SignatureScheme::ED25519
            }
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                SignatureScheme::ECDSA_SECP256R1_SHA256
            }
            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                SignatureScheme::ECDSA_SECP521R1_SHA512
            }
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                SignatureScheme::ED448
            }
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                SignatureScheme::ECDSA_SECP384R1_SHA384
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA44 => SignatureScheme::MLDSA44,
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA65 => SignatureScheme::MLDSA65,
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA87 => SignatureScheme::MLDSA87,
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_128F => {
                SignatureScheme::SLHDSA_SHA2_128F
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_128S => {
                SignatureScheme::SLHDSA_SHA2_128S
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_192F => {
                SignatureScheme::SLHDSA_SHA2_192F
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_192S => {
                SignatureScheme::SLHDSA_SHA2_192S
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_256F => {
                SignatureScheme::SLHDSA_SHA2_256F
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_256S => {
                SignatureScheme::SLHDSA_SHA2_256S
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_128F => {
                SignatureScheme::SLHDSA_SHAKE128F
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_128S => {
                SignatureScheme::SLHDSA_SHAKE128S
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_192F => {
                SignatureScheme::SLHDSA_SHAKE192F
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_192S => {
                SignatureScheme::SLHDSA_SHAKE192S
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_256F => {
                SignatureScheme::SLHDSA_SHAKE256F
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_256S => {
                SignatureScheme::SLHDSA_SHAKE256S
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128F => {
                SignatureScheme::SPHINCS_SHA2_128F
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128S => {
                SignatureScheme::SPHINCS_SHA2_128S
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192F => {
                SignatureScheme::SPHINCS_SHA2_192F
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192S => {
                SignatureScheme::SPHINCS_SHA2_192S
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256F => {
                SignatureScheme::SPHINCS_SHA2_256F
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256S => {
                SignatureScheme::SPHINCS_SHA2_256S
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_128F => {
                SignatureScheme::SPHINCS_SHAKE128F
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_128S => {
                SignatureScheme::SPHINCS_SHAKE128S
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_192F => {
                SignatureScheme::SPHINCS_SHAKE192F
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_192S => {
                SignatureScheme::SPHINCS_SHAKE192S
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_256F => {
                SignatureScheme::SPHINCS_SHAKE256F
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_256S => {
                SignatureScheme::SPHINCS_SHAKE256S
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_512 => {
                SignatureScheme::FALCON_512
            }
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_1024 => {
                SignatureScheme::FALCON_1024
            }
        }
    }

    /// Get the [`AeadType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn aead_algorithm(&self) -> AeadType {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA44
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA65
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA87
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_512
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_1024 => AeadType::Aes128Gcm,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                AeadType::ChaCha20Poly1305
            }
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => AeadType::Aes256Gcm,
        }
    }

    /// Get the [`HpkeKdfType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_kdf_algorithm(&self) -> HpkeKdfType {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Self::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA44
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA65
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA87
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_512
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_1024 => {
                HpkeKdfType::HkdfSha256
            }
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => HpkeKdfType::HkdfSha384,
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                HpkeKdfType::HkdfSha512
            }
        }
    }

    /// Get the [`HpkeKemType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_kem_algorithm(&self) -> HpkeKemType {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA44
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA65
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA87
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_512
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_1024 => {
                HpkeKemType::DhKem25519
            }
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => HpkeKemType::DhKemP256,
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => HpkeKemType::DhKem448,
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => HpkeKemType::DhKemP384,
            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => HpkeKemType::DhKemP521,
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                HpkeKemType::XWingKemDraft6
            }
        }
    }

    /// Get the [`HpkeAeadType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_aead_algorithm(&self) -> HpkeAeadType {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA44
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA65
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA87
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHAKE_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHAKE_256S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_512
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_1024 => {
                HpkeAeadType::AesGcm128
            }
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                HpkeAeadType::ChaCha20Poly1305
            }
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => HpkeAeadType::AesGcm256,
            Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                HpkeAeadType::ChaCha20Poly1305
            }
        }
    }

    /// Get the [`HpkeConfig`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_config(&self) -> HpkeConfig {
        HpkeConfig(
            self.hpke_kem_algorithm(),
            self.hpke_kdf_algorithm(),
            self.hpke_aead_algorithm(),
        )
    }

    /// Get the length of the used hash algorithm.
    #[inline]
    pub const fn hash_length(&self) -> usize {
        self.hash_algorithm().size()
    }

    /// Get the length of the AEAD tag.
    #[inline]
    pub const fn mac_length(&self) -> usize {
        self.aead_algorithm().tag_size()
    }

    /// Returns the key size of the used AEAD.
    #[inline]
    pub const fn aead_key_length(&self) -> usize {
        self.aead_algorithm().key_size()
    }

    /// Returns the length of the nonce of the AEAD.
    #[inline]
    pub const fn aead_nonce_length(&self) -> usize {
        self.aead_algorithm().nonce_size()
    }
}
