extern crate clap;
extern crate env_logger;
extern crate futures;
extern crate nat;
extern crate secp256k1;
extern crate tokio_core;
extern crate tokio_io;

use futures::{Async, AsyncSink, Future, Sink, Stream};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::fmt;
use std::net::{Shutdown, SocketAddr};
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;
use tokio_io::codec::length_delimited::Framed;

use nat::{RendezvousConfig, TcpStreamExt};

// TODO: figure out how to not need this.
struct DummyDebug<S>(S);

impl<S> fmt::Debug for DummyDebug<S> {
    fn fmt(&self, _f: &mut fmt::Formatter) -> fmt::Result {
        Ok(())
    }
}

impl<S: Stream> Stream for DummyDebug<S> {
    type Item = S::Item;
    type Error = S::Error;

    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error> {
        self.0.poll()
    }
}

impl<S: Sink> Sink for DummyDebug<S> {
    type SinkItem = S::SinkItem;
    type SinkError = S::SinkError;

    fn start_send(
        &mut self,
        item: Self::SinkItem,
    ) -> Result<AsyncSink<Self::SinkItem>, Self::SinkError> {
        self.0.start_send(item)
    }

    fn poll_complete(&mut self) -> Result<Async<()>, Self::SinkError> {
        self.0.poll_complete()
    }
}

fn main() {
    env_logger::init();

    let matches = clap::App::new("NAT peer connect")
        .arg(
            clap::Arg::with_name("our-secret")
                .long("our-secret")
                .short("o")
                .takes_value(true)
                .required(true)
                .help("Our secp256k1 secret key base number (type = u8)"),
        )
        .arg(
            clap::Arg::with_name("their-secret")
                .long("their-secret")
                .short("t")
                .takes_value(true)
                .required(true)
                .help("Their secp256k1 secret key base number (type = u8)"),
        )
        .arg(
            clap::Arg::with_name("stun-server")
                .short("s")
                .takes_value(true)
                // .default_value("104.238.181.214:3478")
                .default_value("118.31.229.67:3478")
                .help("STUN server"),
        )
        .arg(
            clap::Arg::with_name("relay-server")
                .short("r")
                .takes_value(true)
                // .default_value("104.238.181.214:20445")
                .default_value("118.31.229.67:9001")
                .help("Relay server"),
        )
        .arg(
            clap::Arg::with_name("message")
                .index(1)
                .required(true)
                .help("The message to send"),
        )
        .get_matches();

    let our_secret: u8 = matches
        .value_of("our-secret")
        .map(|s| u8::from_str_radix(s, 16).unwrap())
        .unwrap();
    let their_secret: u8 = matches
        .value_of("their-secret")
        .map(|s| u8::from_str_radix(s, 16).unwrap())
        .unwrap();
    let stun_server = matches
        .value_of("stun-server")
        .map(|s| s.parse().unwrap())
        .unwrap();
    let relay_server: SocketAddr = matches
        .value_of("relay-server")
        .map(|s| s.parse().unwrap())
        .unwrap();
    let message: Vec<u8> = matches
        .value_of("message")
        .map(|s| String::from(s).into_bytes())
        .unwrap();

    let secp = Secp256k1::new();
    let our_privkey = SecretKey::from_slice(&secp, &[our_secret; 32]).unwrap();
    let their_privkey = SecretKey::from_slice(&secp, &[their_secret; 32]).unwrap();
    let their_pubkey = PublicKey::from_secret_key(&secp, &their_privkey);
    let config = RendezvousConfig {
        stun_server,
        our_privkey,
        their_pubkey,
    };
    println!("config: {:#?}", config);

    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let fut = TcpStream::connect(&relay_server, &handle)
        .map_err(|e| panic!("error connecting to relay server: {:?}", e))
        .and_then(move |relay_stream| {
            let relay_channel = DummyDebug(Framed::new(relay_stream).map(|bytes| bytes.freeze()));
            TcpStream::rendezvous_connect(relay_channel, &handle, &config)
                .map_err(|e| panic!("rendezvous connect failed: {:?}", e))
                .and_then(|stream| {
                    println!("connected!");
                    tokio_io::io::write_all(stream, message)
                        .map_err(|e| panic!("error writing to tcp stream: {:?}", e))
                        .and_then(|(stream, _)| {
                            stream.shutdown(Shutdown::Write).unwrap();
                            tokio_io::io::read_to_end(stream, Vec::new())
                                .map_err(|e| panic!("error reading from tcp stream: {:?}", e))
                                .map(|(_, data)| {
                                    let recv_message = String::from_utf8_lossy(&data);
                                    println!("got message: {} = {:?}", recv_message, data);
                                })
                        })
                })
        });
    core.run(fut).unwrap();
}
