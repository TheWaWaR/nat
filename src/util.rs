use byteorder::{ByteOrder, LittleEndian};
use bytes::Bytes;
use futures::{
    future::{self, loop_fn, Loop},
    stream, Future, Sink, Stream,
};
use net2::TcpBuilder;
use tiny_keccak;
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
            let digest = tiny_keccak::keccak256(&data);
            let msg = Message::from_slice(&digest).unwrap();
            (data, msg)
        })
        .map(|(data, msg)| (data, SECP256K1.sign(&msg, privkey)))
        .map(|(data, sign)| {
            let signature = sign.serialize_compact(&SECP256K1);
            let content_len = signature.len() + data.len();
            let mut all_data = vec![0u8; content_len + 2];
            LittleEndian::write_u16(&mut all_data, content_len as u16);
            all_data[2..66].copy_from_slice(&signature);
            all_data[66..].copy_from_slice(&data);
            all_data
        })
        .unwrap()
}

pub fn recover_data<'a, T>(signed_data: &'a [u8], pubkey: &PublicKey) -> Result<T, RendezvousError>
where
    T: Deserialize<'a>,
{
    let content_len = LittleEndian::read_u16(&signed_data[0..2]) as usize;
    let signature = &signed_data[2..66];
    let data = &signed_data[66..];
    assert_eq!(content_len, signed_data.len() - 2);
    Signature::from_compact(&SECP256K1, signature)
        .map_err(map_error)
        .and_then(move |sign| {
            let digest = tiny_keccak::keccak256(&data);
            let msg = Message::from_slice(&digest).unwrap();
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
