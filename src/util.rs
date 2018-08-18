

use futures::{
    stream,
    Future,
    Stream,
    Sink,
    future::{
        self,
        loop_fn,
        Loop,
    },
};
use tokio::io as async_io;
use tokio_core::{
    reactor::Handle,
    net::{
        TcpStream,
        TcpListener,
    },
};
use net2::TcpBuilder;
use bytes::Bytes;
// use std::time::{Instant, Duration};
use std::net::SocketAddr;
use std::collections::HashSet;
use fibers::{Executor, InPlaceExecutor, Spawn};
use rustun::{Method, Client};
use rustun::client::UdpClient;
use rustun::rfc5389;
use secp256k1::{self, Secp256k1, SecretKey, PublicKey};


lazy_static! {
    pub static ref SECP256K1: Secp256k1<secp256k1::All> = Secp256k1::new();
}

pub type RendezvousNonce = [u8; 32];
pub type BoxFuture<I, E> = Box<Future<Item = I, Error = E>>;
// type BoxStream<I, E> = Box<Stream<Item = I, Error = E>>;


#[derive(Debug, Serialize, Deserialize)]
pub struct RendezvousMsg {
    pub pubkey: PublicKey,
    /// 256bit random data
    pub nonce: RendezvousNonce,
    pub open_addrs: Vec<SocketAddr>,
    pub rendezvous_addr: Option<SocketAddr>,
}

#[derive(Debug)]
pub struct RendezvousConfig {
    pub stun_server: SocketAddr,
    pub our_privkey: SecretKey,
    pub their_pubkey: PublicKey,
}

// FIXME: return a tokio based future
pub fn public_addr_from_stun(server: SocketAddr) -> Vec<SocketAddr> {
    debug!("Connecting to STUN server: {:?}", server);
    let mut executor = InPlaceExecutor::new().unwrap();
    let mut client = UdpClient::new(&executor.handle(), server);
    let request = rfc5389::methods::Binding.request::<rfc5389::Attribute>();
    let monitor = executor.spawn_monitor(client.call(request));

    match executor.run_fiber(monitor)
        .map_err(|err| {
            warn!("STUN error: {:?}", err);
            err
        })
        .unwrap()
        .map_err(|err| {
            warn!("STUN error: {:?}", err);
            err
        })
        .unwrap()
    {
        Ok(resp) => {
            debug!("OK: {:?}", resp);
            resp
                .attributes()
                .into_iter()
                .filter_map(|attr| {
                    match attr {
                        rfc5389::Attribute::XorMappedAddress(addr) => {
                            Some(addr.address())
                        }
                        _ => None
                    }
                })
                .collect::<Vec<SocketAddr>>()
        },
        Err(e) => {
            debug!("ERROR: {:?}", e);
            Vec::new()
        },
    }
}
