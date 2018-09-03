use bytes::Bytes;
use futures::{
    future::{self, loop_fn, Loop},
    stream, Future, Sink, Stream,
};
use net2::TcpBuilder;
use tokio::io as async_io;
use tokio_core::{
    net::{TcpListener, TcpStream},
    reactor::Handle,
};
// use std::time::{Instant, Duration};
use bincode;
use fibers::{Executor, InPlaceExecutor, Spawn};
use rustun::client::UdpClient;
use rustun::rfc5389;
use rustun::{Client, Method};
use secp256k1::{self, Message, PublicKey, Secp256k1, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;

use super::error::{map_error, RendezvousError};

lazy_static! {
    pub static ref SECP256K1: Secp256k1<secp256k1::All> = Secp256k1::new();
}

pub type RendezvousNonce = [u8; 32];
pub type BoxFuture<I, E> = Box<Future<Item = I, Error = E>>;
pub type BoxStream<I, E> = Box<Stream<Item = I, Error = E>>;

#[derive(Debug, Serialize, Deserialize)]
pub struct TcpRendezvousMsg {
    pub pubkey: PublicKey,
    /// 256bit random data
    pub nonce: RendezvousNonce,
    pub open_addrs: Vec<SocketAddr>,
    pub rendezvous_addr: Option<SocketAddr>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UdpRendezvousMsg {
    pub pubkey: PublicKey,
    /// 256bit random data
    pub nonce: RendezvousNonce,
    pub open_addrs: HashSet<SocketAddr>,
    pub rendezvous_addrs: Vec<SocketAddr>,
}

#[derive(Debug)]
pub struct RendezvousConfig {
    pub stun_server: SocketAddr,
    pub our_privkey: SecretKey,
    pub their_pubkey: PublicKey,
}

pub fn sign_data<T: ?Sized>(privkey: &SecretKey, value: &T) -> Vec<u8>
where
    T: Serialize,
{
    bincode::serialize(value)
        .map(|data| {
            let msg = Message::from_slice(&data).unwrap();
            (data, msg)
        })
        .map(|(data, msg)| (data, SECP256K1.sign(&msg, privkey)))
        .map(|(data, sign)| {
            let mut all_data = Vec::new();
            all_data.extend(&data);
            all_data.extend(sign.serialize_compact(&SECP256K1).into_iter());
            all_data
        })
        .unwrap()
}

pub fn recover_data<'a, T>(signed_data: &'a [u8], pubkey: &PublicKey) -> Result<T, RendezvousError>
where
    T: Deserialize<'a>,
{
    let signature = &signed_data[0..64];
    let data = &signed_data[64..];
    Signature::from_compact(&SECP256K1, signature)
        .map_err(map_error)
        .and_then(move |sign| {
            let msg = Message::from_slice(data).unwrap();
            SECP256K1
                .verify(&msg, &sign, pubkey)
                .map(|_| bincode::deserialize(data).unwrap())
                .map_err(map_error)
        })
}

// FIXME: return a tokio based future
pub fn public_addr_from_stun(server: SocketAddr) -> Vec<SocketAddr> {
    debug!("Connecting to STUN server: {:?}", server);
    let mut executor = InPlaceExecutor::new().unwrap();
    let mut client = UdpClient::new(&executor.handle(), server);
    let request = rfc5389::methods::Binding.request::<rfc5389::Attribute>();
    let monitor = executor.spawn_monitor(client.call(request));

    match executor
        .run_fiber(monitor)
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
            resp.attributes()
                .into_iter()
                .filter_map(|attr| match attr {
                    rfc5389::Attribute::XorMappedAddress(addr) => Some(addr.address()),
                    _ => None,
                })
                .collect::<Vec<SocketAddr>>()
        }
        Err(e) => {
            debug!("ERROR: {:?}", e);
            Vec::new()
        }
    }
}
