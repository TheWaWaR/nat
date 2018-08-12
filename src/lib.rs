
extern crate bytes;
#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;
extern crate futures;
extern crate tokio;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate secp256k1;
extern crate bincode;
extern crate get_if_addrs;
extern crate net2;
extern crate igd;
extern crate rustun;

use tokio::{
    net::{
        TcpStream,
    },
};
pub trait TcpStreamExt {
}
