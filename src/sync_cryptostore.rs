use super::*;
use sp_keystore::SyncCryptoStore;

impl SyncCryptoStore for PlayKeystore {
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
        self.inner.sr25519_vrf_sign(key_type, public, transcript_data)
    }
}
