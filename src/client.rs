use std::net::ToSocketAddrs;

use ductile::{ChannelReceiver, ChannelSender};

use super::*;
use sp_keystore::Error;

pub struct Keystore {
    conn_tx: ChannelSender<RemoteKeystore>,
    conn_rx: ChannelReceiver<RemoteKeystoreResponse>,
}

impl Keystore {
    pub fn new(addr: impl ToSocketAddrs) -> Result<Self, String> {
        let (conn_tx, conn_rx) = ductile::connect_channel(addr).map_err(|e| e.to_string())?;

        Ok(Self { conn_tx, conn_rx })
    }
}

impl std::fmt::Debug for Keystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keystore")
    }
}

impl Keystore {
    fn sr25519_public_keys(&self, id: KeyTypeId) -> Vec<sr25519::Public> {
        match self.conn_tx.send(RemoteKeystore::Sr25519PublicKeys(id)) {
            Err(_) => vec![],
            Ok(_) => self
                .conn_rx
                .recv()
                .and_then(|resp| {
                    if let RemoteKeystoreResponse::Sr25519PublicKeys(resp) = resp {
                        Ok(resp)
                    } else {
                        //unreachable!()
                        Ok(vec![])
                    }
                })
                .or_else::<(), _>(|_| Ok(vec![]))
                .unwrap(),
        }
    }

    fn sr25519_generate_new(
        &self,
        id: KeyTypeId,
        seed: Option<&str>,
    ) -> Result<sr25519::Public, Error> {
        match self.conn_tx.send(RemoteKeystore::Sr25519GenerateNew {
            id,
            seed: seed.map(|s| s.to_string()),
        }) {
            Err(_) => Err(Error::Unavailable),
            Ok(_) => self
                .conn_rx
                .recv()
                .map_err(|_| Error::Unavailable)
                .and_then(|resp| {
                    if let RemoteKeystoreResponse::Sr25519GenerateNew(resp) = resp {
                        resp
                    } else {
                        //unreachable!()
                        Err(Error::Unavailable)
                    }
                }),
        }
    }

    fn ed25519_public_keys(&self, id: KeyTypeId) -> Vec<ed25519::Public> {
        match self.conn_tx.send(RemoteKeystore::Ed25519PublicKeys(id)) {
            Err(_) => vec![],
            Ok(_) => self
                .conn_rx
                .recv()
                .and_then(|resp| {
                    if let RemoteKeystoreResponse::Ed25519PublicKeys(resp) = resp {
                        Ok(resp)
                    } else {
                        //unreachable!()
                        Ok(vec![])
                    }
                })
                .or_else::<(), _>(|_| Ok(vec![]))
                .unwrap(),
        }
    }

    fn ed25519_generate_new(
        &self,
        id: KeyTypeId,
        seed: Option<&str>,
    ) -> Result<ed25519::Public, Error> {
        match self.conn_tx.send(RemoteKeystore::Ed25519GenerateNew {
            id,
            seed: seed.map(|s| s.to_string()),
        }) {
            Err(_) => Err(Error::Unavailable),
            Ok(_) => self
                .conn_rx
                .recv()
                .map_err(|_| Error::Unavailable)
                .and_then(|resp| {
                    if let RemoteKeystoreResponse::Ed25519GenerateNew(resp) = resp {
                        resp
                    } else {
                        //unreachable!()
                        Err(Error::Unavailable)
                    }
                }),
        }
    }

    fn ecdsa_public_keys(&self, id: KeyTypeId) -> Vec<ecdsa::Public> {
        match self.conn_tx.send(RemoteKeystore::EcdsaPublicKeys(id)) {
            Err(_) => vec![],
            Ok(_) => self
                .conn_rx
                .recv()
                .and_then(|resp| {
                    if let RemoteKeystoreResponse::EcdsaPublicKeys(resp) = resp {
                        Ok(resp)
                    } else {
                        //unreachable!()
                        Ok(vec![])
                    }
                })
                .or_else::<(), _>(|_| Ok(vec![]))
                .unwrap(),
        }
    }

    fn ecdsa_generate_new(
        &self,
        id: KeyTypeId,
        seed: Option<&str>,
    ) -> Result<ecdsa::Public, Error> {
        match self.conn_tx.send(RemoteKeystore::EcdsaGenerateNew {
            id,
            seed: seed.map(|s| s.to_string()),
        }) {
            Err(_) => Err(Error::Unavailable),
            Ok(_) => self
                .conn_rx
                .recv()
                .map_err(|_| Error::Unavailable)
                .and_then(|resp| {
                    if let RemoteKeystoreResponse::EcdsaGenerateNew(resp) = resp {
                        resp
                    } else {
                        //unreachable!()
                        Err(Error::Unavailable)
                    }
                }),
        }
    }

    fn insert_unknown(&self, key_type: KeyTypeId, suri: &str, public: &[u8]) -> Result<(), ()> {
        match self.conn_tx.send(RemoteKeystore::InsertUnknown {
            id: key_type,
            suri: suri.to_string(),
            public: Vec::from(public),
        }) {
            Err(_) => Err(()),
            Ok(_) => self.conn_rx.recv().map_err(|_| ()).and_then(|resp| {
                if let RemoteKeystoreResponse::InsertUnknown(resp) = resp {
                    resp
                } else {
                    //unreachable!()
                    Err(())
                }
            }),
        }
    }

    fn supported_keys(
        &self,
        id: KeyTypeId,
        keys: Vec<CryptoTypePublicPair>,
    ) -> Result<Vec<CryptoTypePublicPair>, Error> {
        match self
            .conn_tx
            .send(RemoteKeystore::SupportedKeys { id, keys })
        {
            Err(_) => Err(Error::Unavailable),
            Ok(_) => self
                .conn_rx
                .recv()
                .map_err(|_| Error::Unavailable)
                .and_then(|resp| {
                    if let RemoteKeystoreResponse::SupportedKeys(resp) = resp {
                        resp
                    } else {
                        //unreachable!()
                        Err(Error::Unavailable)
                    }
                }),
        }
    }

    fn keys(&self, id: KeyTypeId) -> Result<Vec<CryptoTypePublicPair>, Error> {
        match self.conn_tx.send(RemoteKeystore::Keys(id)) {
            Err(_) => Err(Error::Unavailable),
            Ok(_) => self
                .conn_rx
                .recv()
                .map_err(|_| Error::Unavailable)
                .and_then(|resp| {
                    if let RemoteKeystoreResponse::Keys(resp) = resp {
                        resp
                    } else {
                        //unreachable!()
                        Err(Error::Unavailable)
                    }
                }),
        }
    }

    fn has_keys(&self, public_keys: &[(Vec<u8>, KeyTypeId)]) -> bool {
        match self
            .conn_tx
            .send(RemoteKeystore::HasKeys(public_keys.to_vec()))
        {
            Err(_) => false,
            Ok(_) => self
                .conn_rx
                .recv()
                .and_then(|resp| {
                    if let RemoteKeystoreResponse::HasKeys(resp) = resp {
                        Ok(resp)
                    } else {
                        //unreachable!()
                        Ok(false)
                    }
                })
                .or_else::<(), _>(|_| Ok(false))
                .unwrap(),
        }
    }

    fn sign_with(
        &self,
        id: KeyTypeId,
        key: &CryptoTypePublicPair,
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match self.conn_tx.send(RemoteKeystore::SignWith {
            id,
            key: key.clone(),
            msg: msg.to_vec(),
        }) {
            Err(_) => Err(Error::Unavailable),
            Ok(_) => self
                .conn_rx
                .recv()
                .map_err(|_| Error::Unavailable)
                .and_then(|resp| {
                    if let RemoteKeystoreResponse::SignWith(resp) = resp {
                        resp
                    } else {
                        //unreachable!()
                        Err(Error::Unavailable)
                    }
                }),
        }
    }

    fn sign_with_any(
        &self,
        id: KeyTypeId,
        keys: Vec<CryptoTypePublicPair>,
        msg: &[u8],
    ) -> Result<(CryptoTypePublicPair, Vec<u8>), Error> {
        match self.conn_tx.send(RemoteKeystore::SignWithAny {
            id,
            keys,
            msg: msg.to_vec(),
        }) {
            Err(_) => Err(Error::Unavailable),
            Ok(_) => self
                .conn_rx
                .recv()
                .map_err(|_| Error::Unavailable)
                .and_then(|resp| {
                    if let RemoteKeystoreResponse::SignWithAny(resp) = resp {
                        resp
                    } else {
                        //unreachable!()
                        Err(Error::Unavailable)
                    }
                }),
        }
    }

    fn sign_with_all(
        &self,
        id: KeyTypeId,
        keys: Vec<CryptoTypePublicPair>,
        msg: &[u8],
    ) -> Result<Vec<Result<Vec<u8>, Error>>, ()> {
        match self.conn_tx.send(RemoteKeystore::SignWithAll {
            id,
            keys,
            msg: msg.to_vec(),
        }) {
            Err(_) => Err(()),
            Ok(_) => self.conn_rx.recv().map_err(|_| ()).and_then(|resp| {
                if let RemoteKeystoreResponse::SignWithAll(resp) = resp {
                    resp
                } else {
                    //unreachable!()
                    Err(())
                }
            }),
        }
    }

    // fn sr25519_vrf_sign(
    //     &self,
    //     key_type: KeyTypeId,
    //     public: &sr25519::Public,
    //     transcript_data: sp_keystore::vrf::VRFTranscriptData,
    // ) -> Result<sp_keystore::vrf::VRFSignature, Error> {
    //     match self.conn_tx.send(RemoteKeystore::Sr25519VrfSign {
    //         key_type,
    //         public: *public,
    //         transcript_data,
    //     }) {
    //         Err(_) => Err(Error::Unavailable),
    //         Ok(_) => self
    //             .conn_rx
    //             .recv()
    //             .map_err(|_| Error::Unavailable)
    //             .and_then(|resp| {
    //                 if let RemoteKeystoreResponse::Sr25519VrfSign(resp) = resp {
    //                     resp
    //                 } else {
    //                     //unreachable!()
    //                     Err(Error::Unavailable)
    //                 }
    //             }),
    //     }
    // }
}

mod sync_cryptostore {
    use super::*;

    impl sp_keystore::SyncCryptoStore for Keystore {
        fn sr25519_public_keys(&self, id: KeyTypeId) -> Vec<sr25519::Public> {
            self.sr25519_public_keys(id)
        }

        fn sr25519_generate_new(
            &self,
            id: KeyTypeId,
            seed: Option<&str>,
        ) -> Result<sr25519::Public, sp_keystore::Error> {
            self.sr25519_generate_new(id, seed)
        }

        fn ed25519_public_keys(&self, id: KeyTypeId) -> Vec<ed25519::Public> {
            self.ed25519_public_keys(id)
        }

        fn ed25519_generate_new(
            &self,
            id: KeyTypeId,
            seed: Option<&str>,
        ) -> Result<ed25519::Public, sp_keystore::Error> {
            self.ed25519_generate_new(id, seed)
        }

        fn ecdsa_public_keys(&self, id: KeyTypeId) -> Vec<ecdsa::Public> {
            self.ecdsa_public_keys(id)
        }

        fn ecdsa_generate_new(
            &self,
            id: KeyTypeId,
            seed: Option<&str>,
        ) -> Result<ecdsa::Public, sp_keystore::Error> {
            self.ecdsa_generate_new(id, seed)
        }

        fn insert_unknown(&self, id: KeyTypeId, suri: &str, public: &[u8]) -> Result<(), ()> {
            self.insert_unknown(id, suri, public)
        }

        fn supported_keys(
            &self,
            id: KeyTypeId,
            keys: Vec<CryptoTypePublicPair>,
        ) -> Result<Vec<CryptoTypePublicPair>, sp_keystore::Error> {
            self.supported_keys(id, keys)
        }

        fn keys(&self, id: KeyTypeId) -> Result<Vec<CryptoTypePublicPair>, sp_keystore::Error> {
            self.keys(id)
        }

        fn has_keys(&self, public_keys: &[(Vec<u8>, KeyTypeId)]) -> bool {
            self.has_keys(public_keys)
        }

        fn sign_with(
            &self,
            id: KeyTypeId,
            key: &CryptoTypePublicPair,
            msg: &[u8],
        ) -> Result<Vec<u8>, sp_keystore::Error> {
            self.sign_with(id, key, msg)
        }

        fn sr25519_vrf_sign(
            &self,
            _: KeyTypeId,
            _: &sr25519::Public,
            _: sp_keystore::vrf::VRFTranscriptData,
        ) -> Result<sp_keystore::vrf::VRFSignature, sp_keystore::Error> {
            // self.sr25519_vrf_sign(key_type, public, transcript_data)
            Err(Error::Unavailable)
        }
    }
}

mod cryptostore {
    use super::*;
    use async_trait::async_trait;

    #[async_trait]
    impl sp_keystore::CryptoStore for Keystore {
        async fn sr25519_public_keys(&self, id: KeyTypeId) -> Vec<sr25519::Public> {
            self.sr25519_public_keys(id)
        }

        async fn sr25519_generate_new(
            &self,
            id: KeyTypeId,
            seed: Option<&str>,
        ) -> Result<sr25519::Public, sp_keystore::Error> {
            self.sr25519_generate_new(id, seed)
        }

        async fn ed25519_public_keys(&self, id: KeyTypeId) -> Vec<ed25519::Public> {
            self.ed25519_public_keys(id)
        }

        async fn ed25519_generate_new(
            &self,
            id: KeyTypeId,
            seed: Option<&str>,
        ) -> Result<ed25519::Public, sp_keystore::Error> {
            self.ed25519_generate_new(id, seed)
        }

        async fn ecdsa_public_keys(&self, id: KeyTypeId) -> Vec<ecdsa::Public> {
            self.ecdsa_public_keys(id)
        }

        async fn ecdsa_generate_new(
            &self,
            id: KeyTypeId,
            seed: Option<&str>,
        ) -> Result<ecdsa::Public, sp_keystore::Error> {
            self.ecdsa_generate_new(id, seed)
        }

        async fn insert_unknown(&self, id: KeyTypeId, suri: &str, public: &[u8]) -> Result<(), ()> {
            self.insert_unknown(id, suri, public)
        }

        async fn supported_keys(
            &self,
            id: KeyTypeId,
            keys: Vec<CryptoTypePublicPair>,
        ) -> Result<Vec<CryptoTypePublicPair>, sp_keystore::Error> {
            self.supported_keys(id, keys)
        }

        async fn keys(&self, id: KeyTypeId) -> Result<Vec<CryptoTypePublicPair>, sp_keystore::Error> {
            self.keys(id)
        }

        async fn has_keys(&self, public_keys: &[(Vec<u8>, KeyTypeId)]) -> bool {
            self.has_keys(public_keys)
        }

        async fn sign_with(
            &self,
            id: KeyTypeId,
            key: &CryptoTypePublicPair,
            msg: &[u8],
        ) -> Result<Vec<u8>, sp_keystore::Error> {
            self.sign_with(id, key, msg)
        }

        async fn sr25519_vrf_sign(
            &self,
            _: KeyTypeId,
            _: &sr25519::Public,
            _: sp_keystore::vrf::VRFTranscriptData,
        ) -> Result<sp_keystore::vrf::VRFSignature, sp_keystore::Error> {
            // self.sr25519_vrf_sign(key_type, public, transcript_data)
            Err(Error::Unavailable)
        }
    }
}
