use sp_core::{
    crypto::{CryptoTypePublicPair, KeyTypeId},
    ecdsa, ed25519, sr25519,
};
use sp_keystore::{Error, vrf::{VRFSignature, VRFTranscriptData}};

use serde::{Serialize, Deserialize};

#[macro_use]
extern crate tracing;

#[derive(Serialize, Deserialize)]
pub enum RemoteKeystore {
    Sr25519PublicKeys(KeyTypeId),
    Sr25519GenerateNew {
        id: KeyTypeId,
        seed: Option<String>,
    },
    Ed25519PublicKeys(KeyTypeId),
    Ed25519GenerateNew {
        id: KeyTypeId,
        seed: Option<String>,
    },
    EcdsaPublicKeys(KeyTypeId),
    EcdsaGenerateNew {
        id: KeyTypeId,
        seed: Option<String>,
    },
    InsertUnknown {
        id: KeyTypeId,
        suri: String,
        public: Vec<u8>,
    },
    SupportedKeys {
        id: KeyTypeId,
        keys: Vec<CryptoTypePublicPair>,
    },
    Keys(KeyTypeId),
    HasKeys(Vec<(Vec<u8>, KeyTypeId)>),
    SignWith {
        id: KeyTypeId,
        key: CryptoTypePublicPair,
        msg: Vec<u8>
    },
    SignWithAny {
        id: KeyTypeId,
        keys: Vec<CryptoTypePublicPair>,
        msg: Vec<u8>,
    },
    SignWithAll {
        id: KeyTypeId,
        keys: Vec<CryptoTypePublicPair>,
        msg: Vec<u8>,
    },
    Sr25519VrfSign {
        key_type: KeyTypeId,
        public: sr25519::Public,
        transcript_data: VRFTranscriptData,
    }
}

#[derive(Serialize, Deserialize)]
pub enum RemoteKeystoreResponse {
    Sr25519PublicKeys(Vec<sr25519::Public>),
    Sr25519GenerateNew(Result<sr25519::Public, Error>),
    Ed25519PublicKeys(Vec<ed25519::Public>),
    Ed25519GenerateNew(Result<ed25519::Public, Error>),
    EcdsaPublicKeys(Vec<ecdsa::Public>),
    EcdsaGenerateNew(Result<ecdsa::Public, Error>),
    InsertUnknown(Result<(), ()>),
    SupportedKeys(Result<Vec<CryptoTypePublicPair>, Error>),
    Keys(Result<Vec<CryptoTypePublicPair>, Error>),
    HasKeys(bool),
    SignWith(Result<Vec<u8>, Error>),
    SignWithAny(Result<(CryptoTypePublicPair, Vec<u8>), Error>),
    SignWithAll(Result<Vec<Result<Vec<u8>, Error>>, ()>),
    Sr25519VrfSign(Result<VRFSignature, Error>)
}

impl RemoteKeystore {
    fn exec<K: sp_keystore::SyncCryptoStore>(self, keystore: &K) -> RemoteKeystoreResponse {
        use sp_keystore::SyncCryptoStore;

        match self {
            RemoteKeystore::Sr25519PublicKeys(id) => {
                let resp = SyncCryptoStore::sr25519_public_keys(keystore, id);
                RemoteKeystoreResponse::Sr25519PublicKeys(resp)
            }
            RemoteKeystore::Sr25519GenerateNew { id, seed } => {
                let resp = SyncCryptoStore::sr25519_generate_new(keystore, id, seed.map(|s| s.as_str()));
                RemoteKeystoreResponse::Sr25519GenerateNew(resp)
            }
            RemoteKeystore::Ed25519PublicKeys(id) => {
                let resp = SyncCryptoStore::ed25519_public_keys(keystore, id);
                RemoteKeystoreResponse::Ed25519PublicKeys(resp)
            }
            RemoteKeystore::Ed25519GenerateNew { id, seed } => {
                let resp = SyncCryptoStore::ed25519_generate_new(keystore, id, seed.map(|s| s.as_str()));
                RemoteKeystoreResponse::Ed25519GenerateNew(resp)
            }
            RemoteKeystore::EcdsaPublicKeys(id) => {
                let resp = SyncCryptoStore::ecdsa_public_keys(keystore, id);
                RemoteKeystoreResponse::EcdsaPublicKeys(resp)
            }
            RemoteKeystore::EcdsaGenerateNew { id, seed } => {
                let resp = SyncCryptoStore::ecdsa_generate_new(keystore, id, seed.map(|s| s.as_str()));
                RemoteKeystoreResponse::EcdsaGenerateNew(resp)
            }
            RemoteKeystore::InsertUnknown { id, suri, public } => {
                let resp = SyncCryptoStore::insert_unknown(keystore, id, &suri, public.as_slice());
                RemoteKeystoreResponse::InsertUnknown(resp)
            }
            RemoteKeystore::SupportedKeys { id, keys } => {
                let resp = SyncCryptoStore::supported_keys(keystore, id, keys);
                RemoteKeystoreResponse::SupportedKeys(resp)
            }
            RemoteKeystore::Keys(id) => {
                let resp = SyncCryptoStore::keys(keystore, id);
                RemoteKeystoreResponse::Keys(resp)
            }
            RemoteKeystore::HasKeys(id) => {
                let resp = SyncCryptoStore::has_keys(keystore, id.as_slice());
                RemoteKeystoreResponse::HasKeys(resp)
            }
            RemoteKeystore::SignWith { id, key, msg } => {
                let resp = SyncCryptoStore::sign_with(keystore, id, &key, msg.as_slice());
                RemoteKeystoreResponse::SignWith(resp)
            }
            RemoteKeystore::SignWithAny { id, keys, msg } => {
                let resp = SyncCryptoStore::sign_with_any(keystore, id, keys, msg.as_slice());
                RemoteKeystoreResponse::SignWithAny(resp)
            }
            RemoteKeystore::SignWithAll { id, keys, msg } => {
                let resp = SyncCryptoStore::sign_with_all(keystore, id, keys, msg.as_slice());
                RemoteKeystoreResponse::SignWithAll(resp)
            }
            RemoteKeystore::Sr25519VrfSign { key_type, public, transcript_data } => {
                let resp = SyncCryptoStore::sr25519_vrf_sign(keystore, key_type, &public, transcript_data);
                RemoteKeystoreResponse::Sr25519VrfSign(resp)
            }
        }
    }
}

#[cfg(feature = "client")]
pub mod client;
