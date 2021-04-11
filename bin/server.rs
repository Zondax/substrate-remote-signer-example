mod keystore;
use keystore::Keystore;

use ductile::{ChannelReceiver, ChannelSender};
use serde::{Deserialize, Serialize};

use tcp_keystore::{RemoteKeystore, RemoteKeystoreResponse};

#[macro_use]
extern crate tracing;

fn main() {
    tracing_subscriber::fmt::init();
    let listener = ductile::ChannelServer::bind("localhost:10710").expect("unable to bind server");

    for (tx, rx, peer) in listener {
        info!(?peer, "NEW connection");

        std::thread::spawn(move || {
            debug_span!("handling requests", ?peer);
            logic(tx, rx);
        });
    }
}

fn logic(tx: ChannelSender<RemoteKeystoreResponse>, rx: ChannelReceiver<RemoteKeystore>) {
    let ks = Keystore::new();

    auto_provision(&ks).expect("couldn't provision keystore");

    while let Ok(req) = rx.recv() {
        debug!(request = ?req);
        let resp = req.exec(&ks);
        debug!(response = ?resp);
        tx.send(resp).expect("unable to send to peer");
    }
}

fn auto_provision(inner: &Keystore) -> Result<(), sp_keystore::Error> {
    use sp_core::crypto::{key_types, KeyTypeId};
    use sp_keystore::SyncCryptoStore;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const NEEDED_KEYS: &[KeyTypeId] = &[key_types::BABE, key_types::AURA, key_types::GRANDPA];

    for key_type in NEEDED_KEYS.iter() {
        inner.sr25519_generate_new(*key_type, Some(MNEMONIC))?;
        inner.ed25519_generate_new(*key_type, Some(MNEMONIC))?;
        inner.ecdsa_generate_new(*key_type, Some(MNEMONIC))?;
    }

    Ok(())
}
