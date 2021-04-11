use sc_keystore::LocalKeystore;
use sp_core::{
    crypto::{key_types, CryptoTypePublicPair, KeyTypeId},
    ecdsa, ed25519, sr25519,
};
use sp_keystore::Error;

pub struct Keystore {
    inner: LocalKeystore,
}

impl std::fmt::Debug for Keystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keystore")
    }
}

impl Keystore {
    pub fn new() -> Self {
        let inner = LocalKeystore::in_memory();
        Self { inner }
    }
}

mod sync_cryptostore {
    use super::*;
    use sp_keystore::SyncCryptoStore;

    impl SyncCryptoStore for Keystore {
        fn sr25519_public_keys(&self, id: KeyTypeId) -> Vec<sr25519::Public> {
            //execute_fut(self.sr25519_public_keys_impl(id), &self.runtime)
            self.inner.sr25519_public_keys(id)
        }

        fn sr25519_generate_new(
            &self,
            id: KeyTypeId,
            seed: Option<&str>,
        ) -> Result<sr25519::Public, sp_keystore::Error> {
            //execute_fut(self.sr25519_generate_new_impl(id, seed), &self.runtime)
            self.inner.sr25519_generate_new(id, seed)
        }

        fn ed25519_public_keys(&self, id: KeyTypeId) -> Vec<ed25519::Public> {
            self.inner.ed25519_public_keys(id)
        }

        fn ed25519_generate_new(
            &self,
            id: KeyTypeId,
            seed: Option<&str>,
        ) -> Result<ed25519::Public, sp_keystore::Error> {
            self.inner.ed25519_generate_new(id, seed)
        }

        fn ecdsa_public_keys(&self, id: KeyTypeId) -> Vec<ecdsa::Public> {
            self.inner.ecdsa_public_keys(id)
        }

        fn ecdsa_generate_new(
            &self,
            id: KeyTypeId,
            seed: Option<&str>,
        ) -> Result<ecdsa::Public, sp_keystore::Error> {
            self.inner.ecdsa_generate_new(id, seed)
        }

        fn insert_unknown(&self, key_type: KeyTypeId, suri: &str, public: &[u8]) -> Result<(), ()> {
            self.inner.insert_unknown(key_type, suri, public)
        }

        fn supported_keys(
            &self,
            id: KeyTypeId,
            keys: Vec<CryptoTypePublicPair>,
        ) -> Result<Vec<CryptoTypePublicPair>, sp_keystore::Error> {
            self.inner.supported_keys(id, keys)
        }

        fn has_keys(&self, public_keys: &[(Vec<u8>, KeyTypeId)]) -> bool {
            self.inner.has_keys(public_keys)
        }

        fn sign_with(
            &self,
            id: KeyTypeId,
            key: &CryptoTypePublicPair,
            msg: &[u8],
        ) -> Result<Vec<u8>, sp_keystore::Error> {
            // execute_fut(self.sign_with_impl(id, key, msg), &self.runtime)
            self.inner.sign_with(id, key, msg)
        }

        fn sr25519_vrf_sign(
            &self,
            key_type: KeyTypeId,
            public: &sr25519::Public,
            transcript_data: sp_keystore::vrf::VRFTranscriptData,
        ) -> Result<sp_keystore::vrf::VRFSignature, sp_keystore::Error> {
            self.inner
                .sr25519_vrf_sign(key_type, public, transcript_data)
        }
    }
}

mod cryptostore {
use super::*;
use async_trait::async_trait;
use sp_keystore::CryptoStore;

#[async_trait]
impl CryptoStore for Keystore {
    async fn sr25519_public_keys(&self, id: KeyTypeId) -> Vec<sr25519::Public> {
        self.inner.sr25519_public_keys(id).await
    }

    async fn sr25519_generate_new(
        &self,
        id: KeyTypeId,
        seed: Option<&str>,
    ) -> Result<sr25519::Public, sp_keystore::Error> {
        self.inner.sr25519_generate_new(id, seed).await
    }

    async fn ed25519_public_keys(&self, id: KeyTypeId) -> Vec<ed25519::Public> {
        self.inner.ed25519_public_keys(id).await
    }

    async fn ed25519_generate_new(
        &self,
        id: KeyTypeId,
        seed: Option<&str>,
    ) -> Result<ed25519::Public, sp_keystore::Error> {
        self.inner.ed25519_generate_new(id, seed).await
    }

    async fn ecdsa_public_keys(&self, id: KeyTypeId) -> Vec<ecdsa::Public> {
        self.inner.ecdsa_public_keys(id).await
    }

    async fn ecdsa_generate_new(
        &self,
        id: KeyTypeId,
        seed: Option<&str>,
    ) -> Result<ecdsa::Public, sp_keystore::Error> {
        self.inner.ecdsa_generate_new(id, seed).await
    }

    async fn insert_unknown(&self, id: KeyTypeId, suri: &str, public: &[u8]) -> Result<(), ()> {
        self.inner.insert_unknown(id, suri, public).await
    }

    async fn supported_keys(
        &self,
        id: KeyTypeId,
        keys: Vec<CryptoTypePublicPair>,
    ) -> Result<Vec<CryptoTypePublicPair>, sp_keystore::Error> {
        self.inner.supported_keys(id, keys).await
    }

    async fn keys(&self, id: KeyTypeId) -> Result<Vec<CryptoTypePublicPair>, sp_keystore::Error> {
        self.inner.keys(id).await
    }

    async fn has_keys(&self, public_keys: &[(Vec<u8>, KeyTypeId)]) -> bool {
        self.inner.has_keys(public_keys).await
    }

    async fn sign_with(
        &self,
        id: KeyTypeId,
        key: &CryptoTypePublicPair,
        msg: &[u8],
    ) -> Result<Vec<u8>, sp_keystore::Error> {
        self.inner.sign_with(id, key, msg).await
    }

    async fn sr25519_vrf_sign(
        &self,
        key_type: KeyTypeId,
        public: &sr25519::Public,
        transcript_data: sp_keystore::vrf::VRFTranscriptData,
    ) -> Result<sp_keystore::vrf::VRFSignature, sp_keystore::Error> {
        self.inner.sr25519_vrf_sign(key_type, public, transcript_data).await
    }
}

}
