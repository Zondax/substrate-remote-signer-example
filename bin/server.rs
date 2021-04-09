mod keystore;
use keystore::Keystore;

use ductile::{ChannelReceiver, ChannelSender};
use serde::{Deserialize, Serialize};

use tcp_keystore::{RemoteKeystore, RemoteKeystoreResponse};

#[macro_use]
extern crate tracing;

fn main() {
    let listener = ductile::ChannelServer("localhost:10710").expect("unable to bind server");

    for (tx, rx, peer) in listener {
        info!("NEW peer connection: {:?}", peer);

        std::thread::spawn(|| {
            debug_span!("handling requests for {:?}", peer);
            logic(tx, rx);
        })
    }
}

fn logic<S: Serialize, R: Deserialize>(
    tx: ChannelSender<RemoteKeystoreResponse>,
    rx: ChannelReceiver<RemoteKeystore>,
) {

    let mut ks = Keystore::new();

    while let Ok(req) = tx.recv() {
        let resp = req.exec(&ks);
        rx.send(resp).expect("unable to send to peer");
    }
}
