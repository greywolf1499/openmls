//! # OpenMLS Custom PQC Capable Crypto Provider
//!
//! This is an implementation of the [`OpenMlsProvider`] trait to use with
//! OpenMLS.

pub use openmls_memory_storage::{MemoryStorage, MemoryStorageError};
use openmls_traits::OpenMlsProvider;

mod provider;
pub use provider::*;

#[derive(Default, Debug)]
#[cfg_attr(feature = "test-utils", derive(Clone))]
pub struct OpenMlsPqcProvider {
    crypto: PqcCrypto,
    key_store: MemoryStorage,
}

impl OpenMlsProvider for OpenMlsPqcProvider {
    type CryptoProvider = PqcCrypto;
    type RandProvider = PqcCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.key_store
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
