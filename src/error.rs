use std::fmt;

#[derive(Debug)]
pub enum RendezvousError {
    /// FIXME: Just a placeholder
    Any(String),
}

pub fn map_error<E: fmt::Debug>(e: E) -> RendezvousError {
    println!(">> map_error: {:?}", e);
    RendezvousError::Any(format!("{:?}", e))
}
