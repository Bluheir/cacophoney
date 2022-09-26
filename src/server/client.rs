use std::{collections::HashSet, error::Error, fmt::Display};

use futures::{channel::mpsc, select, AsyncReadExt, FutureExt, StreamExt};
use quinn::{NewConnection, RecvStream};

use crate::data::{crypto::PubKey, Identifier, Message};

#[derive(Debug)]
pub struct CancelError;

impl Error for CancelError {}
impl Display for CancelError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "the read from the stream was cancelled")
    }
}

pub struct Client {
    pub receive: ClientReceiver,
    pub identities: HashSet<PubKey>,
}

impl Client {
    pub fn new(receive: ClientReceiver) -> Self {
        Self {
            receive,
            identities: HashSet::default(),
        }
    }
}

pub struct ClientReceiver {
    canceller: mpsc::UnboundedReceiver<()>,
    stream: RecvStream,
}

impl ClientReceiver {
    /// Creates a new client receiver
    pub fn new(canceller: mpsc::UnboundedReceiver<()>, stream: RecvStream) -> Self {
        Self { canceller, stream }
    }
    /// Helper method to receive bytes and be cancellable by an unbounded receiver
    pub async fn receive(&mut self) -> Result<Message, Box<dyn Error>> {
        let mut buf = Vec::with_capacity(512);

        // Reading from the stream
        let mut fut1 = AsyncReadExt::read_to_end(&mut self.stream, &mut buf).fuse();
        // Reading from the receiver
        let mut fut2 = self.canceller.next().fuse();

        select! {
            v1 = fut1 => v1,
            // The receive was cancelled
            _ = fut2 => return Err(Box::new(CancelError{}))
        }?;

        // Deserialize the bytes
        let a = serde_cbor::from_slice::<Message>(buf.as_ref())?;
        Ok(a)
    }
}

pub async fn handle_connection(connection: NewConnection) -> Result<(), Box<dyn Error>> {
    // Create a bidirectional stream from the new connection
    let (_send, recv) = connection.connection.open_bi().await?;
    // Create an unbounded channel that can cancel a receive
    let (_c_send, c_recv) = mpsc::unbounded();
    // Create a wrapper receiver
    let mut receiver = ClientReceiver::new(c_recv, recv);

    while let Ok(msg) = receiver.receive().await {
        match msg.header {
            // 0: IDENTIFY HEADER
            // The client identifies themselves with a public key, with a signature of the time hashed together with their IP address
            0 => {
                let _obj = serde_cbor::value::from_value::<Identifier>(msg.object);
            }
            _ => {}
        }
    }

    Ok(())
}
