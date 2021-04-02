use super::*;
use async_trait::async_trait;
use sp_keystore::CryptoStore;

#[async_trait]
impl CryptoStore for TEEKeystore {
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
