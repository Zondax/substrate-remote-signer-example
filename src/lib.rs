use sp_core::{
    crypto::{CryptoTypePublicPair, KeyTypeId},
    ecdsa, ed25519, sr25519,
};
use sc_keystore::LocalKeystore;

mod sync_cryptostore;
mod cryptostore;

#[macro_use]
extern crate tracing;

/// A local keystore we can mess around with
pub struct PlayKeystore {
    inner: LocalKeystore,
}

impl std::fmt::Debug for PlayKeystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PlayKeystore")
    }
}

impl PlayKeystore {
    #[instrument]
    pub fn new() -> Self {
        let mut inner = LocalKeystore::in_memory();

        Self { inner }
    }
}
